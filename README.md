# PI102825 Group Creater

PI102825 relates to devices failing to renew their MDM profile when the built-in Jamf CA needs to be renewed in organisations with over 500 devices.

To use the script, download and run `sh pi102825_group_creater.sh <name of static group, a number starting at 1 will be added> [ full jss URL ]` You can use either username/password or oauth (ie API Client) credentials. If you use oath, be sure to add the appropriate roles as listed below. 

Run without arguments for syntax full syntax and examples.

For more information on this PI, please contact Jamf support.

## API Roles

The following roles will be needed...
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

