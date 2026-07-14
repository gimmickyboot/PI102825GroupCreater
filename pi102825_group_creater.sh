#!/bin/sh

###################
# pi102825_group_creater.sh - script to create static groups of devices for PI102825
# https://github.com/gimmickyboot/PI102825GroupCreater-jamf
#
# v1.4 (14/07/2026)
###################
## uncomment the next line to output debugging to stdout
#set -x

###############################################################################
## variable declarations
# shellcheck disable=SC2034
ME=$(basename "$0")
# shellcheck disable=SC2034
BINPATH=$(dirname "$0")
logFile="${HOME}/Library/Logs/$(basename "${ME}" .sh).log"
grpSize=100  # must not be greater than 100
CLEANUP=false

###############################################################################
## function declarations

statMsg() {
  # function to send messages to the log file. send second arg to output to stdout
  # usage: statMsg "<message to send>" [ "" ]

  if [ $# -gt 1 ]; then
    # send message to stdout
    printf '%s\n' "$1"
  fi
  
  printf '%s\n' "$(/bin/date "+%Y-%m-%d %H:%M:%S"): $1" >> "${logFile}"

}

apiRead() {
  # $1 = endpoint, ie JSSResource/policies or api/v1/computers-inventory?section=GENERAL&page=0&page-size=100&sort=general.name%3Aasc
  # $2 = acceptType, ie json or xml, xml is default
  # usage: apiRead "JSSResource/computergroups/id/0" [ "json" ]
  
  if [ $# -eq 1 ]; then
    acceptType="xml"
  else
    acceptType="$2"
  fi
  /usr/bin/curl -b "${stickySess}" -s -X GET "${jssURL}${1}" -H "Accept: application/${acceptType}" -H "Authorization: Bearer ${apiToken}"

}

apiPost() {
  # $1 = endpoint, ie JSSResource/mobiledevices/id/0 or api/v3/computers-inventory
  # $2 = data
  # $3 = contentType, ie json or xml, xml is default
  # usage: apiPost "JSSResource/computergroups/id/0" "<some data>" [ "json" ]

  if [ $# -eq 2 ]; then
    contentType="xml"
  else
    contentType="$3"
  fi

  /usr/bin/curl -b "${stickySess}" -s -w "\n%{http_code}" -X POST "${jssURL}${1}" -H "Content-Type: application/${contentType}" -H "Authorization: Bearer ${apiToken}" -d "${2}"
}

apiDelete() {
  # $1 = endpoint, ie JSSResource/computergroups/id/${readResult}
  # $2 = acceptYpe, ie json or xml, xml is default
  # usage: apiDelete "JSSResource/computergroups/id/${readResult}" [ "json" ]

  if [ $# -eq 1 ]; then
    acceptType="xml"
  else
    acceptType="$2"
  fi

  /usr/bin/curl -b "${stickySess}" -s -X DELETE "${jssURL}${1}" -H "Accept: application/${acceptType}" -H "Authorization: Bearer ${apiToken}"

}

processTokenExpiry() {
  # returns apiTokenExpiresEpochUTC
  # time is UTC!!!
  # usage: processTokenExpiry
  
  if [ "${apiUsername}" ]; then
    apiTokenExpiresLongUTC=$(printf '%s' "${authTokenJson}" | /usr/bin/jq -r .expires | /usr/bin/awk -F . '{ print $1 }')
    apiTokenExpiresEpochUTC=$(/bin/date -u -j -f "%Y-%m-%dT%T" "${apiTokenExpiresLongUTC}" +"%s")
  else
    apiTokenExpiresInSec=$(printf '%s' "${authTokenJson}" | /usr/bin/jq -r .expires_in)
    epochNowUTC=$(/bin/date -u '+%s')
    apiTokenExpiresEpochUTC=$((apiTokenExpiresInSec+epochNowUTC-15))
  fi

}

renewToken(){
  # renews a near expiring token
  # usage: renewToken

  if [ "${apiUsername}" ] && [ "${epochDiff}" -le 0 ]; then
    authTokenJson=$(/usr/bin/curl -b "${stickySess}" -s "${jssURL}api/v1/auth/token" -X POST -H "Authorization: Basic ${baseCreds}")
    apiToken=$(printf '%s' "${authTokenJson}" | /usr/bin/jq -r .token)
  elif  [ "${apiUsername}" ] && [ "${epochDiff}" -le 30 ]; then
    authTokenJson=$(/usr/bin/curl -b "${stickySess}" -s -X POST "${jssURL}api/v1/auth/keep-alive" -H "Authorization: Bearer ${apiToken}")
    apiToken=$(printf '%s' "${authTokenJson}" | /usr/bin/jq -r .token)
  else
    authTokenJson=$(/usr/bin/curl -b "${stickySess}" -s "${jssURL}api/oauth/token" -H "Content-Type: application/x-www-form-urlencoded" --data-urlencode "client_id=${clientID}" --data-urlencode "grant_type=client_credentials" --data-urlencode "client_secret=${clientSecret}")
    apiToken=$(printf '%s' "${authTokenJson}" | /usr/bin/jq -r .access_token)
  fi

  # process the token's expiry
  processTokenExpiry

}

checkToken() {
  # check the token expiry
  # usage: checkToken

  epochNowUTC=$(/bin/date -u +"%s")
  epochDiff=$((apiTokenExpiresEpochUTC - epochNowUTC))
  if [ "${epochDiff}" -le 0 ]; then
    statMsg "Token has expired. Renewing"
    renewToken
  elif [ "${epochDiff}" -lt 30 ]; then
    statMsg "Token nearing expiry (${epochDiff}s). Renewing"
    renewToken
  else
    statMsg "Token valid (${epochDiff}s left)"
  fi

}

destroyToken() {
  # destroys the token
  # usage: destroyToken

  if [ ! "${premExit}" ]; then
    statMsg "Destroying the token"
    responseCode=$(/usr/bin/curl -b "${stickySess}" -w "%{http_code}" -s -X POST "${jssURL}api/v1/auth/invalidate-token" -o /dev/null -H "Authorization: Bearer ${apiToken}")
    case "${responseCode}" in
      204)
        statMsg "Token has been destroyed"
        ;;

      401)
        statMsg "Token already invalid"
        ;;

      *)
        statMsg "An unknown error has occurred destroying the token"
        ;;
    esac

    authTokenRAW=""
    authTokenJson=""
    apiToken=""
    apiTokenExpiresEpochUTC="0"
  fi

}

usage() {
    cat << EOF

Create static groups, enough for ${grpSize} devices per group

  usage: ${ME} <name of static group, a number starting at 1 will be added> [ --cleanup ] [ full jss URL ]


  eg ${ME} "MDM Renewal Devices group"
     ${ME} "MDM Renewal Devices group" "https://myco.jamfcloud.com"

EOF
  premExit=1
  exit 1

}

###############################################################################
## start the script here
trap destroyToken EXIT

# check that we have enough args
if [ $# -lt 1 ]; then
  usage
else
  # clear the terminal
  clear
fi

theGroupName=$1
shift

while [ "$#" -gt 0 ]; do
  case "$1" in
      --cleanup)
          CLEANUP=true
          ;;

      http://*|https://*)
          if [ -n "${jssURL}" ]; then
              printf '%s\n' "Error: URL specified more than once" >&2
              usage
          fi
          jssURL=$1
          ;;

      *)
          printf '%s\n' "Unknown argument: $1" >&2
          usage
          ;;
  esac
  shift
done

# verify we have a jssURL. Ask if we don't
if [ ! "${jssURL}" ]; then
  statMsg "No jssURL passed as an argument. Reading from this Mac"
  jssURL=$(/usr/libexec/PlistBuddy -c "Print :jss_url" /Library/Preferences/com.jamfsoftware.jamf.plist)
fi
until /usr/bin/curl --connect-timeout 5 -s "${jssURL}"; do
  printf '\n'
  statMsg "jssURL is invalid or none found on this Mac" ""
  printf '\n%s' "Enter a JSS URL, eg https://jss.jamfcloud.com:8443/ (leave blank to exit): "
  unset jssURL
  read -r jssURL
  if [ ! "${jssURL}" ]; then
    printf '\n'
    premExit=1
    exit 0
  fi
done

# make sure we have a trailing /
lastChar=$(printf '%s' "${jssURL}" | rev | /usr/bin/cut -c 1 -)
case "${lastChar}" in
  "/")
    printf '%s\n' "GOOD" >/dev/null 2>&1
    ;;

  *)
    jssURL="${jssURL}/"
    ;;
esac

printf '\n'
statMsg "jssURL ${jssURL} is valid. Continuing" ""

statMsg "Getting the sticky session"
# https://developer.jamf.com/jamf-pro/docs/sticky-sessions-for-jamf-cloud
stickySess=$(/usr/bin/curl -s --head "${jssURL}" |  /usr/bin/grep -i "^set-cookie" |  /usr/bin/grep -E "APBALANCED|jpro-ingress" |  /usr/bin/awk '{print $2}' |  /usr/bin/sed 's/.$//')

while : ; do
  printf '\n%s' "Choose the type of authentication, Username/password (U or u) or API roles and clients (R or r) (leave blank to exit): "
  read -r authChoice
  if [ ! "${authChoice}" ]; then
    printf '\n'
    premExit=1
    exit 0
  fi

  case "${authChoice}" in
    U|u)
      # get user creds and token
      while : ; do
        statMsg "Username/password has been chosen for authentication"
        printf '\n%s' "Enter your API username (leave blank to exit): "
        read -r apiUsername
        if [ ! "${apiUsername}" ]; then
          printf '\n'
          premExit=1
          exit 0
        fi
        printf '\n%s' "Enter your API password (no echo): "
        stty -echo
        read -r apiPassword
        stty echo
        printf '\n'

        baseCreds=$(printf "%s:%s" "${apiUsername}" "${apiPassword}" | /usr/bin/iconv -t ISO-8859-1 | /usr/bin/base64 -i -)

        # get the token
        authTokenRAW=$(/usr/bin/curl -b "${stickySess}" -s -w "%{http_code}" "${jssURL}api/v1/auth/token" -X POST -H "Authorization: Basic ${baseCreds}")
        authTokenJson=$(printf '%s' "${authTokenRAW}" | /usr/bin/sed -e '$s/...$//' )
        httpCode=$(printf '%s' "${authTokenRAW}" | /usr/bin/tail -c 3)
        case "${httpCode}" in
          200)
            statMsg "Authentication successful" ""
            statMsg "Token created successfully"

            # strip out the token
            apiToken=$(printf '%s' "${authTokenJson}" | /usr/bin/jq -r .token)

            # process the token's expiry
            processTokenExpiry

            # unset apiPassword
            break 2
            ;;

          *)
            printf '\nError getting token. HTTP Status code: %s\n\nPlease try again.\n\n' "${httpCode}"
            premExit=1
            continue
            ;;
        esac
      done

      ;;

    R|r)
      statMsg "Username/password has been chosen for authentication"
      statMsg "API roles and clients has been chosen" ""
      printf '\n'
      while : ; do
        printf '\n%s' "Enter your client id (leave blank to exit): "
        read -r clientID
        if [ ! "${clientID}" ]; then
          printf '\n'
          premExit=1
          exit 0
        fi

        printf '\n%s' "Enter your client id (leave blank to exit): "
        printf "Enter your client secret (no echo): "
        stty -echo
        read -r clientSecret
        stty echo

        authTokenRAW=$(/usr/bin/curl -b "${stickySess}" -s -w "%{http_code}" "${jssURL}api/oauth/token" -H "Content-Type: application/x-www-form-urlencoded" --data-urlencode "client_id=${clientID}" --data-urlencode "grant_type=client_credentials" --data-urlencode "client_secret=${clientSecret}")
        authTokenJson=$(printf '%s' "${authTokenRAW}" | /usr/bin/sed -e '$s/...$//' )
        httpCode=$(printf '%s' "${authTokenRAW}" | /usr/bin/tail -c 3)
        case "${httpCode}" in
          200)
            printf '%s\n'
            printf '%s\n' "Token created successfully"

            # strip out the token
            apiToken=$(printf '%s' "${authTokenJson}" | /usr/bin/jq -r .access_token)
            processTokenExpiry

            # unset clientSecret
            break 2
            ;;

          *)
            printf '\nError getting token. http error code is: %s\n\nPlease try again.\n\n' "${httpCode}"
            premExit=1
            continue
            ;;
        esac


      done
      ;;

       *)
        printf '\n%s' "Unknown choice. Please try again. Leave blank to exit."
        ;;
      esac
done

# create the missing MDM profile EA for monitoring
statMsg "Creating the monitoring EA"
# shellcheck disable=SC2016
responseEA=$(/usr/bin/curl -b "${stickySess}" -s -w "\n%{http_code}" -X POST "${jssURL}api/v1/computer-extension-attributes" -H "Authorization: Bearer ${apiToken}" -H "Content-Type: application/json" \
  -d '{
  "name": "PI102825 - No MDM Profile",
  "description": "Monitoring EA for PI102825",
  "dataType": "STRING",
  "popupMenuChoices": [],
  "ldapAttributeMapping": "",
  "ldapExtensionAttributeAllowed": null,
  "inventoryDisplayType": "GENERAL",
  "inputType": "SCRIPT",
  "scriptContents": "#!/bin/bash\nmdmProfile=$(/usr/libexec/mdmclient QueryInstalledProfiles | grep \"00000000-0000-0000-A000-4A414D460003\")\nif [[ $mdmProfile == \"\" ]]; then\n            result=\"MDM Profile Not Installed\"\nelse\n            result=\"MDM Profile Installed\"\nfi\necho \"<result>$result</result>\"",
  "enabled": true,
  "manageExistingData": null
}')
responseCode=$(printf '%s' "${responseEA}" | /usr/bin/tail -n 1)
case "${responseCode}" in
  201)
    statMsg "Successfully created the EA \"PI102825 - No MDM Profile\""
    ;;

  *)
      statMsg "EA already exists."
      statMsg "$(printf '%s' "${responseEA}" | /usr/bin/sed '$d' | /usr/bin/jq -r '.errors[].description')" ""
    ;;
esac

sleep 1

# create the smart group for the EA
statMsg "Creating the smart group for EA monitoring"
responseSM=$(/usr/bin/curl -b "${stickySess}" -s -w "\n%{http_code}" -X POST "${jssURL}api/v2/computer-groups/smart-groups" -H "Authorization: Bearer ${apiToken}" -H "Content-Type: application/json" \
  -d '{
  "name": "PI102825 - No MDM Profile",
  "description": "Monitoring for PI102825",
  "criteria": [
    {
      "name": "PI102825 - No MDM Profile",
      "priority": 0,
      "andOr": "and",
      "searchType": "is",
      "value": "MDM Profile Not Installed",
      "openingParen": false,
      "closingParen": false
    }
  ],
  "siteId": "-1"
}')
responseCode=$(/bin/echo "${responseSM}" | /usr/bin/tail -n 1)
case "${responseCode}" in
  201)
    statMsg "Successfully created the smart group \"PI102825 - No MDM Profile\""
    ;;

  *)
    statMsg "$(/bin/echo "${responseSM}" | /usr/bin/sed '$d' | /usr/bin/jq -r '.errors[].description')" ""
    ;;
esac

# delete any previous static computer groups
if [ "${CLEANUP}" = "true" ]; then
  grpNum=1
  while : ; do
    encodedGroupName=$(printf '%s' "${theGroupName} ${grpNum}" | /usr/bin/xxd -p | /usr/bin/sed 's/\(..\)/%\1/g' | /usr/bin/tr -d '\n')
    readResult=$(apiRead "JSSResource/computergroups/name/${encodedGroupName}" | /usr/bin/xmllint --xpath '//computer_group/id/text()' - 2>/dev/null)
    if [ "${readResult}" ]; then
      statMsg "Computer static group ${theGroupName} ${grpNum} deleted." ""
      apiDelete "JSSResource/computergroups/id/${readResult}" >/dev/null 2>&1
      grpNum=$((grpNum+1))
    else
      break
    fi

    sleep 1
  done
  totalCompDeleted=$((grpNum-1))

  # delete any previous static mobile device groups
  grpNum=1
  while : ; do
    encodedGroupName=$(printf '%s' "${theGroupName} ${grpNum}" | /usr/bin/xxd -p | /usr/bin/sed 's/\(..\)/%\1/g' | /usr/bin/tr -d '\n')
    readResult=$(apiRead "api/v1/mobile-device-groups/static-groups?page=0&page-size=100&sort=groupId%3Aasc&filter=groupName%3D%3D%22${encodedGroupName}%22" "json" | /usr/bin/jq -r '.results[].groupId')
    if [ "${readResult}" ]; then
      statMsg "Mobile Device static group ${theGroupName} ${grpNum} deleted." ""
      apiDelete "api/v1/mobile-device-groups/static-groups/${readResult}" "json" >/dev/null 2>&1
      grpNum=$((grpNum+1))
    else
      break
    fi

    sleep 1
  done
  totalMobDevDeleted=$((grpNum-1))
else
  encodedGroupName=$(printf '%s' "${theGroupName} 1" | /usr/bin/xxd -p | /usr/bin/sed 's/\(..\)/%\1/g' | /usr/bin/tr -d '\n')
  compGrpReadResult=$(/usr/bin/curl -b "${stickySess}" -s -w "%{http_code}" -X GET "${jssURL}JSSResource/computergroups/name/${encodedGroupName}" -H "Authorization: Bearer ${apiToken}" -o /dev/null)
  # mobDevGrpReadResult=$(/usr/bin/curl -s -w "%{http_code}" -X GET "${jssURL}api/v1/mobile-device-groups/static-groups?page=0&page-size=100&sort=groupId%3Aasc&filter=groupName%3D%3D%22${encodedGroupName}%22" -H "Authorization: Bearer ${apiToken}" -o /dev/null)
  mobDevGrpReadResult=$(/usr/bin/curl -b "${stickySess}" -s -X GET "${jssURL}api/v1/mobile-device-groups/static-groups?page=0&page-size=100&sort=groupId%3Aasc&filter=groupName%3D%3D%22${encodedGroupName}%22" -H "Authorization: Bearer ${apiToken}" | /usr/bin/jq -r '.totalCount')
  if [ "${compGrpReadResult}" = "200" ] || [ "${mobDevGrpReadResult}" -gt 0 ]; then
    statMsg "ERROR: Pre-existing groups already exist. Please re-run with --cleanup or choose a different group name" ""
    exit 1
  fi
fi

# if [ "${totalCompDeleted}" ] || [ "${totalMobDevDeleted}" ]; then
#   # sleep here while we wait for the d/b to catch up
#   sleep 15
# fi

checkToken

TMPDIR=$(mktemp -d)

compTmpDir="${TMPDIR}/computers"
mkdir "${compTmpDir}"
pageNum=0
grpNum=1
totalCompCount=$(apiRead "api/v1/computers-inventory?section=HARDWARE&filter=general.remoteManagement.managed%3D%3D%22true%22" "json" | /usr/bin/jq -r .totalCount)
totalCompGroups=$(( (totalCompCount + grpSize - 1) / 100))
while [ $grpNum -le $totalCompGroups ]; do
  serialList=$(apiRead "api/v1/computers-inventory?section=HARDWARE&page=${pageNum}&page-size=${grpSize}&sort=general.name%3Aasc&filter=general.remoteManagement.managed%3D%3D%22true%22" "json" | /usr/bin/jq -r .results[].hardware.serialNumber)
  FILEOUT="${compTmpDir}/${grpNum}.xml"

  # write out the xml header
  cat << EOF > "${FILEOUT}"
<?xml version="1.0" encoding="UTF-8"?><computer_group><name>${theGroupName} ${grpNum}</name><is_smart>false</is_smart><computers>
EOF

  # write out the serials
  printf "%s\n" "$serialList" | while read -r theSerial; do
    cat << EOF >> "${FILEOUT}"
<computer><serial_number>${theSerial}</serial_number></computer>
EOF
  done

  # write out the xml footer
  cat << EOF >> "${FILEOUT}"
</computers></computer_group>
EOF

  statMsg "Adding Computer group ${theGroupName} ${grpNum}" ""
  # responseCreate=$(/usr/bin/curl -b "${stickySess}" -s -w "\n%{http_code}" -X POST "${jssURL}JSSResource/computergroups/id/0" -H "Content-Type: application/xml" -H "Authorization: Bearer ${apiToken}" --data "$(cat "${FILEOUT}")")
  responseCreate=$(apiPost "JSSResource/computergroups/id/0" "$(cat "${FILEOUT}")")
  responseCode=$(/bin/echo "${responseCreate}" | /usr/bin/tail -n 1)
  case "${responseCode}" in
    200|201)
      statMsg "Successfully created the Computer static group ${theGroupName} ${grpNum}"
      ;;

    *)
      statMsg "An error creating the Computer static group ${theGroupName} ${grpNum} occurred."
      echo "${responseCreate}"
      ;;
  esac

  pageNum=$((pageNum+1))
  grpNum=$((grpNum+1))
  checkToken
  sleep 2
done
totalCompCreataed=$((grpNum-1))
statMsg "Finished creating required static Computer groups" ""

mobDevTmpDir="${TMPDIR}/mobiledevices"
mkdir "${mobDevTmpDir}"
pageNum=0
grpNum=1
totalMobDevCount=$(apiRead "api/v2/mobile-devices/detail?section=HARDWARE&filter=managed%3D%3Dtrue" "json" | /usr/bin/jq -r .totalCount)
totalMobDevGroups=$(( (totalMobDevCount + grpSize - 1) / 100))
while [ $grpNum -le $totalMobDevGroups ]; do
  idList=$(apiRead "api/v2/mobile-devices/detail?section=HARDWARE&page-size=${grpSize}&page=${pageNum}&filter=managed%3D%3Dtrue" "json" | /usr/bin/jq -r '.results[].mobileDeviceId')
  FILEOUT="${mobDevTmpDir}/${grpNum}.json"

  # write out the json header
  cat << EOF > "${FILEOUT}"
{
    "groupName": "${theGroupName} ${grpNum}",
    "groupDescription": "${theGroupName} ${grpNum}",
    "siteId": "-1",
    "assignments": [
EOF

  # write out the serials
  printf "%s\n" "$idList" | while read -r theID; do
    cat << EOF >> "${FILEOUT}"
        {
            "mobileDeviceId": "$theID",
            "selected": true
        },
EOF
  done

  # need to remove the last character, ie the ","
  /usr/bin/sed -i '' '$s/.*/        }/' "${FILEOUT}"

  # write out the xml footer
  cat << EOF >> "${FILEOUT}"
    ]
}
EOF

  statMsg "Adding Mobile Device group ${theGroupName} ${grpNum}" ""
  responseCreate=$(apiPost "api/v1/mobile-device-groups/static-groups?platform=false" "$(cat "${FILEOUT}")" "json")
  responseCode=$(/bin/echo "${responseCreate}" | /usr/bin/tail -n 1)
  case "${responseCode}" in
    200|201)
      statMsg "Successfully created the Mobile Device static group ${theGroupName} ${grpNum}"
      ;;

    *)
      statMsg "An error creating the Mobile Device static group ${theGroupName} ${grpNum} occurred."
      ;;
  esac

  pageNum=$((pageNum+1))
  grpNum=$((grpNum+1))
  checkToken
  sleep 2
done
totalMobDevCreataed=$((grpNum-1))
statMsg "Finished creating required static Mobile Device groups" ""

cat << EOF

  Creation summary:

  Total static Computer groups deleted: ${totalCompDeleted}
  Total static Mobile Device groups deleted: ${totalMobDevDeleted}
  Total static Computer groups created: ${totalCompCreataed}
  Total static Mobile Device groups created: ${totalMobDevCreataed}

  Refer to ${logFile} for more information

EOF
