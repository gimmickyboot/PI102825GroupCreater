# PI102825 Group Creater

PI102825 relates to devices failing to renew their MDM profile when the built-in Jamf CA needs to be renewed in organisations with over 500 devices.

To use the script, download and run `sh pi102825_group_creater.sh <name of static group, a number starting at 1 will be added> [ --cleanup ] [ full jss URL ]` You can use either username/password or oauth (ie API Client) credentials. See [Permissions](#permissions) section below for more information on the required privileges or API roles.

Run without arguments for full syntax and examples.
```
% sh pi102825_group_creater.sh   

Create static groups, enough for 100 devices per group

  usage: pi102825_group_creater.sh <name of static group, a number starting at 1 will be added> [ --cleanup ] [ full jss URL ]


  eg pi102825_group_creater.sh "MDM Renewal Devices group"
     pi102825_group_creater.sh "MDM Renewal Devices group" "https://myco.jamfcloud.com"
```
### Notes
- Script will exit if re-existing groups are found. Run with `--cleanup` to override
- The JSS URL is optional. If none is specified, the script will attempt to detect the URL from the Mac the script is running on. If none is found, you will be asked to enter one.

For more information on this PI, please contact Jamf support.

## Permissions

### User accounts and groups privileges
Jamf Pro Server Object
- Create Computer extension attributes
- Read Computers
- Read Mobile Devices
- Create/Read/Delete Static Computer Groups
- Create/Read/Delete Static Mobile Device Groups

### API Roles
- Delete Static Computer Groups
- Read Static Mobile Device Groups
- Read Mobile Devices
- Create Static Computer Groups
- Read Computers
- Create Smart Computer Groups
- Read Static Computer Groups
- Create Computer Extension Attributes
- Delete Static Mobile Device Groups
- Create Static Mobile Device Groups
