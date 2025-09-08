#!/bin/sh

###################
# pi102825_group_creater.sh - script to create static groups of devices for PI102825
# Shannon Pasto <shannon.pasto@jamf.com>
#
# v1.0 (08/09/2025)
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
grpSize=100

###############################################################################
## function declarations

statMsg() {
  # function to send messages to the log file. send second arg to output to stdout
  # usage: statMsg "<message to send>" [ "" ]

  if [ $# -gt 1 ]; then
    # send message to stdout
    /bin/echo "$1"
  fi
  
  /bin/echo "$(/bin/date "+%Y-%m-%d %H:%M:%S"): $1" >> "${logFile}"

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
  /usr/bin/curl -s -X GET "${jssURL}${1}" -H "Accept: application/${acceptType}" -H "Authorization: Bearer ${apiToken}"

}

processTokenExpiry() {
  # returns apiTokenExpiresEpochUTC
  # time is UTC!!!
  # usage: processTokenExpiry
  
  apiTokenExpiresLongUTC=$(/bin/echo "${authTokenJson}" | /usr/bin/jq -r .expires | /usr/bin/awk -F . '{ print $1 }')
  apiTokenExpiresEpochUTC=$(/bin/date -j -f "%Y-%m-%dT%T" "${apiTokenExpiresLongUTC}" +"%s")

}

renewToken(){
  # renews a near expiring token
  # usage: renewToken
  
  authTokenJson=$(/usr/bin/curl -s -X POST "${jssURL}api/v1/auth/keep-alive" -H "Authorization: Bearer ${apiToken}")
  # strip out the token
  apiToken=$(/bin/echo "${authTokenJson}" | /usr/bin/jq -r .token)
  # process the token's expiry
  processTokenExpiry

}

checkToken() {
  # check the token expiry
  # usage: checkToken
  
  epochNowUTC=$(/bin/date -jf "%Y-%m-%dT%T" "$(date -u +"%Y-%m-%dT%T")" +"%s")
  epochDiff=$((apiTokenExpiresEpochUTC - epochNowUTC))
  if [ "${epochDiff}" -gt 119 ]; then
    statMsg "Token still valid." >/dev/null 2>&1
  elif [ "${epochDiff}" -lt 120 ] && [ ${epochDiff} -gt 29 ]; then
    statMsg "Token nearing expiry. Renewing"
    renewToken
  else
    statMsg "Token has expired. Renewing"
    renewToken
  fi

}

destroyToken() {
  # destroys the token
  # usage: destroyToken
  
  if [ ! "${premExit}" ]; then
    statMsg "Destroying the token"
    responseCode=$(/usr/bin/curl -w "%{http_code}" -s -X POST "${jssURL}api/v1/auth/invalidate-token" -o /dev/null -H "Authorization: Bearer ${apiToken}")
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

convertRaw() {
  # convert jamf date to excel date
  # $1 is raw timestamp from Jamf, eg 2024-07-11T13:21:08.175Z
  # usage: convertRaw "2024-07-11T13:21:08.175Z"
  
  trimmedStamp=$(/bin/echo "$1" | /usr/bin/cut -d . -f -1 -)
  /bin/date -juf "%Y-%m-%dT%H:%M:%S" "${trimmedStamp}" +"%d/%m/%y %H:%M"

}

###############################################################################
## start the script here
trap destroyToken EXIT

# check that we have enough args
if [ $# -ne 0 ]; then
  authSuccess=1
  theGroupName="$1"
  if [ $# -eq 2 ]; then
    jssURL=$2
  fi
  # clear the terminal
  clear
else
  cat << EOF

Create static groups, enough for ${grpSize} Macs per group

  usage: ${ME} <name of static group, a number starting at 1 will be added> [ full jss URL ]
  
  eg ${ME} "MDM Renewal Devices group"

EOF
  premExit=1
  exit 1
fi

# verify we have a jssURL. Ask if we don't
if [ ! "${jssURL}" ]; then
  jssURL=$(/usr/libexec/PlistBuddy -c "Print :jss_url" /Library/Preferences/com.jamfsoftware.jamf.plist)
fi
until /usr/bin/curl --connect-timeout 5 -s "${jssURL}"; do
  /bin/echo ""
  /bin/echo "jssURL is invalid"
  /bin/echo ""
  printf "Enter a JSS URL, eg https://jss.jamfcloud.com:8443/ (leave blank to exit): "
  unset jssURL
  read -r jssURL
  if [ ! "${jssURL}" ]; then
    /bin/echo ""
    premExit=1
    exit 0
  fi
done

# make sure we have a trailing /
lastChar=$(/bin/echo "${jssURL}" | rev | /usr/bin/cut -c 1 -)
case "${lastChar}" in
  "/")
    /bin/echo "GOOD" >/dev/null 2>&1
    ;;

  *)
    jssURL="${jssURL}/"
    ;;
esac

/bin/echo ""
statMsg "jssURL ${jssURL} is valid. Continuing" ""

# get user creds and token
while [ "${authSuccess}" -ne 0 ]; do
  /bin/echo ""
  printf "Enter your API username (leave blank to exit): "
  read -r apiUsername
  if [ ! "${apiUsername}" ]; then
    /bin/echo ""
    premExit=1
    exit 0
  fi
  /bin/echo ""
  printf "Enter your API password (no echo): "
  stty -echo
  read -r apiPassword
  stty echo
  echo ""

  baseCreds=$(printf "%s:%s" "${apiUsername}" "${apiPassword}" | /usr/bin/iconv -t ISO-8859-1 | /usr/bin/base64 -i -)

  # get the token
  authTokenRAW=$(/usr/bin/curl -s -w "%{http_code}" "${jssURL}api/v1/auth/token" -X POST -H "Authorization: Basic ${baseCreds}")
  authTokenJson=${authTokenRAW%???}
  httpCode=${authTokenRAW#"$authTokenJson"}
  case "${httpCode}" in
    200)
      statMsg "Authentication successful" ""
      statMsg "Token created successfully"
      authSuccess=0
      unset apiPassword
      ;;

    *)
      printf '\nError getting token. HTTP Status code: %s\n\nPlease try again.\n\n' "${httpCode}"
      premExit=1
      ;;
  esac

done

# strip out the token
apiToken=$(/bin/echo "${authTokenJson}" | /usr/bin/jq -r .token)

# process the token's expiry
processTokenExpiry

TMPDIR=$(mktemp -d)
pageNum=0
grpNum=1
while : ; do
  # check if the group already exists. If it does, delete it
  encodedGroupName=$(printf '%s' "${theGroupName} ${grpNum}" | /usr/bin/xxd -p | /usr/bin/sed 's/\(..\)/%\1/g' | /usr/bin/tr -d '\n')
  readResult=$(apiRead "JSSResource/computergroups/name/${encodedGroupName}" | /usr/bin/xmllint --xpath '//computer_group/id/text()' - 2>/dev/null)
  if [ "${readResult}" ]; then
    statMsg "Group ${theGroupName} ${grpNum} exists. Deleting..."
    # apiDelete "" >/dev/null 2>&1
    /usr/bin/curl -s -X DELETE "${jssURL}JSSResource/computergroups/id/${readResult}" -H "Accept: application/xml" -H "Authorization: Bearer ${apiToken}" >/dev/null 2>&1
  else
    statMsg "Group ${theGroupName} ${grpNum} doesn't exist. Continuing..."
  fi
    
  serialList=$(apiRead "api/v1/computers-inventory?section=HARDWARE&page-size=${grpSize}&page=${pageNum}" "json" | /usr/bin/jq -r .results[].hardware.serialNumber)
  FILEOUT="${TMPDIR}/${grpNum}.xml"
  
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

  statMsg "Adding group ${theGroupName} ${grpNum}" ""
  /usr/bin/curl -s "${jssURL}JSSResource/computergroups/id/0" -H "Content-Type: application/xml" -H "Authorization: Bearer ${apiToken}" --data "$(cat "${FILEOUT}")" >/dev/null 2>&1
  
  if [ "$(/bin/echo "${serialList}" | /usr/bin/wc -l | /usr/bin/xargs)" -ne "${grpSize}" ]; then
    /bin/rm -rf "${TMPDIR}"
    break
  fi
  
  pageNum=$((pageNum+1))
  grpNum=$((grpNum+1))
  checkToken
  sleep 2
done
