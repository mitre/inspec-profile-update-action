control 'SV-234096' do
  title 'The Tanium Server http directory and sub-directories must be restricted with appropriate permissions.'
  desc 'Discretionary Access Control (DAC) is based on the notion that individual users are "owners" of objects and therefore have discretion over who should be authorized to access the object and in which mode (e.g., read or write). Ownership is usually acquired as a consequence of creating the object or via specified ownership assignment. DAC allows the owner to determine who will have access to objects they control. An example of DAC includes user controlled file permissions.

When discretionary access control policies are implemented, subjects are not constrained with regard to what actions they can take with information for which they have already been granted access. Thus, subjects that have been granted access to information are not prevented from passing (i.e., the subjects have the discretion to pass) the information to other subjects or objects. A subject that is constrained in its operation by Mandatory Access Control policies is still able to operate under the less rigorous constraints of this requirement. Thus, while Mandatory Access Control imposes constraints preventing a subject from passing information to another subject operating at a different sensitivity level, this requirement permits the subject to pass the information to any subject at the same sensitivity level. The policy is bounded by the information system boundary. Once the information is passed outside of the control of the information system, additional means may be required to ensure the constraints remain in effect. While the older, more traditional definitions of discretionary access control require identity-based access control, that limitation is not required for this use of discretionary access control.'
  desc 'check', 'Access the Tanium Server interactively.

Log on to the server with an account that has administrative privileges.

Open an Explorer window.

Navigate to Program Files >> Tanium >> Tanium Server.

Right-click on the "Tanium Server\\http" folder.

Select "Properties".

Select the "Security" tab.

Click on the "Advanced" button.

Validate Folder Inheritance is disabled.

Validate the owner of the directory is the [Tanium service account].

Validate the [Tanium Admins] group has full permissions.

Validate System has Read-Only permissions.

Right-click on the "Tanium Server\\http\\libraries" folder.

Select the "Security" tab.

Click on the "Advanced" button. 

Validate Folder Inheritance is disabled. 

Validate the owner of the directory is the [Tanium service account]. 

Validate System has Read-Only permissions. 

Validate the [Tanium service account] has Read-Only permissions. 

Validate the [Tanium Admins] group has full permissions.

Right-click on the "Tanium Server\\http\\taniumjs" folder.

Select the "Security" tab.

Click on the "Advanced" button.

Validate Folder Inheritance is disabled.

Validate the owner of the directory is the [Tanium service account].

Validate System has "Read-Only" permissions.

Validate the [Tanium service account] has "Read-Only" permissions.

Validate the [Tanium Admins] group has full permissions.

Right-click on the "Tanium Server\\http\\tux" folder.

Select the "Security" tab.

Click on the "Advanced" button.

Validate Folder Inheritance is disabled.

Validate the owner of the directory is the [Tanium service account].

Validate System has "Read-Only" permissions.

Validate the [Tanium service account] has "Read Only" permissions.

Validate the [Tanium Admins] group has full permissions.

Right-click on the "Tanium Server\\http\\tux-console" folder.

Select the "Security" tab.

Click on the "Advanced" button.

Validate Folder Inheritance is disabled.

Validate the owner of the directory is the [Tanium service account].

Validate System has "Read-Only" permissions.

Validate the [Tanium service account] has "Read-Only" permissions.

Validate the [Tanium Admins] group has full permissions.

Right-click on the "Tanium Server\\Logs" folder.

Select "Properties".

Select the "Security" tab.

Click on the "Advanced" button.

Validate Folder Inheritance is disabled.

Validate the owner of the directory is the [Tanium service account].

Validate the [Tanium Service Account] has only "Modify" permissions.

Validate the [Tanium Admins] group has full permissions.

Right-click on the "Tanium Server\\TDL_Logs" folder.

Select "Properties".

Select the "Security" tab.

Click on the "Advanced" button.

Validate Folder Inheritance is disabled.

Validate the owner of the directory is the [Tanium service account].

Validate the [Tanium Service Account] has only "Modify" permissions.

Validate the [Tanium Admins] group has full permissions.

Right-click on the "Tanium Server\\Certs" folder.

Select "Properties".

Select the "Security" tab.

Click on the "Advanced" button.

Validate Folder Inheritance is disabled.

Validate the owner of the directory is the [Tanium service account].

Validate System has "Read-Only" permissions.

Validate the [Tanium Admins] group has full permissions.

Navigate to Tanium Server >> Certs.

For the following files verify System and [Tanium Service Account] have "Read-Only" permissions:

installedcacert.crt
installed-server.crt
installed-server.key
SOAPServer.crt
SOAPServer.key

Right-click on the "Tanium Server\\content_public_keys" folder.

Select "Properties".

Select the "Security" tab.

Click on the "Advanced" button.

Validate Folder Inheritance is disabled.

Validate the owner of the directory is the [Tanium service account].

Validate System has "Read-Only" permissions.

Validate the [Tanium Service Account] has "Read-Only" permissions.

Validate the [Tanium Admins] group has full permissions.

If any of the above permissions are not configured correctly, this is a finding.'
  desc 'fix', 'Access the Tanium Server interactively.

Log on to the server with an account that has administrative privileges.

Open an Explorer window.

Navigate to Program Files >> Tanium >> Tanium Server.

Right-click on the "Tanium Server\\http folder.

Select "Properties". 

Select the "Security" tab.

Click on the "Advanced" button.

Verify/Disable folder inheritance.

Change/verify the owner of the directory to the [Tanium service account].

Change/verify the [Tanium Admins] group has full permissions.

Reduce System to "Read-Only" permissions.

Right-click on the "Tanium Server\\http\\libraries" folder.

Select the "Security" tab.

Click on the "Advanced" button.

Verify/Disable folder inheritance.

Change/verify the owner of the directory to the [Tanium service account].

Reduce System to "Read-Only" permissions.

Reduce [Tanium service account] to "Read-Only" permissions.

Change/verify the [Tanium Admins] group has full permissions.

Right-click on the "Tanium Server\\http\\taniumjs" folder.

Select the "Security" tab.

Click on the "Advanced" button.

Verify/Disable folder inheritance.

Change/verify the owner of the directory to the [Tanium service account].

Reduce System to "Read-Only" permissions.

Reduce [Tanium service account] to "Read-Only" permissions.

Change/verify the [Tanium Admins] group has full permissions.

Right-click on the "Tanium Server\\http\\tux" folder.

Select the "Security" tab.

Click on the "Advanced" button.

Verify/Disable folder inheritance.

Change/verify the owner of the directory to the [Tanium service account].

Reduce System to "Read-Only" permissions.

Reduce [Tanium service account] to "Read-Only" permissions.

Change/verify the [Tanium Admins] group has full permissions.

Right-click on the "Tanium Server\\http\\tux-console" folder.

Select the "Security" tab.

Click on the "Advanced" button.

Verify/Disable folder inheritance.

Change/verify the owner of the directory to the [Tanium service account].

Reduce System to "Read-Only" permissions.

Reduce [Tanium service account] to "Read-Only" permissions.

Change/verify the [Tanium Admins] group has full permissions.

Right-click on the "Tanium Server\\Logs" folder.

Select the "Security" tab.

Click on the "Advanced" button.

Verify/Disable folder inheritance.

Change/verify the owner of the directory to the [Tanium service account].

Reduce [Tanium service account] to "Modify" permissions.

Change/verify the [Tanium Admins] group has full permissions.

Right-click on the "Tanium Server\\http\\TDL_Logs" folder.

Select the "Security" tab.

Click on the "Advanced" button.

Verify/Disable folder inheritance.

Change/verify the owner of the directory to the [Tanium service account].

Reduce [Tanium service account] to "Modify" permissions.

Change/verify the [Tanium Admins] group has full permissions.

Right-click on the "Tanium Server\\Certs" folder.

Select the "Security" tab.

Click on the "Advanced" button.

Verify/Disable folder inheritance.

Change/verify the owner of the directory to the [Tanium service account].

Reduce System to "Read-Only" permissions.

Change/verify the [Tanium Admins] group has full permissions.

Navigate to Tanium Server >> Certs.

For the following files verify/reduce System and [Tanium Service Account] to "Read-Only" permissions:

installedcacert.crt
installed-server.crt
installed-server.key
SOAPServer.crt
SOAPServer.key

Right-click on the "Tanium Server\\content_public_keys" folder.

Select the "Security" tab.

Click on the "Advanced" button.

Verify/Disable folder inheritance.

Change/verify the owner of the directory to the [Tanium service account].

Reduce System to "Read-Only" permissions - apply to child objects.

Reduce [Tanium service account] to "Read-Only" permissions - apply to child objects.

Change/verify the [Tanium Admins] group has full permissions.'
  impact 0.5
  ref 'DPMS Target Tanium 7.3'
  tag check_id: 'C-37281r610788_chk'
  tag severity: 'medium'
  tag gid: 'V-234096'
  tag rid: 'SV-234096r612749_rule'
  tag stig_id: 'TANS-SV-000025'
  tag gtitle: 'SRG-APP-000328'
  tag fix_id: 'F-37246r610789_fix'
  tag 'documentable'
  tag legacy: ['SV-102265', 'V-92163']
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end
