control 'SV-104505' do
  title 'Symantec ProxySG must protect the Web Management Console, SSH, and command line interface (CLI) from unauthorized modification.'
  desc 'Protecting audit data also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit data.

Network devices providing tools to interface with audit data will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user enjoys in order to make access decisions regarding the access to audit tools.

Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.'
  desc 'check', '1. Obtain a list of authorized personnel and IP addresses that should have access to the Web Management Console or CLI.
2. Log on to the Web Management Console.
3. Click Configuration >> Policy >> Visual Policy Manager.
4. Click "Launch", select the "Admin Access" layer.
5. Verify any users and/or groups listed in the "source" field of each rule have the appropriate "Action" of either "Allow Read/Write access" or "Allow Read-only Access" per the user/group’s assigned privileges.
6. Verify that the users and/or groups have the "Service" set to "SSH-Console", "HTTPS-Console", or both, depending on the user/group’s assigned privileges.

If the Symantec ProxySG is not configured to protect the Web Management Console, SSH, and CLI from unauthorized modification, this is a finding.'
  desc 'fix', '1. Obtain a list of authorized personnel and IP addresses that should have access to the Web Management Console or CLI.
2. Log on to the Web Management Console.
3. Click Configuration >> Policy >> Visual Policy Manager.
4. Click "Launch", select the "Admin Access" layer.
5. For every user and/or group listed in the "source" field of each rule, set the "Action" to either "Allow Read/Write access" or "Allow Read-only Access" per the user/group’s assigned privileges.
6. For every user/group, also set the "Service" to "SSH-Console", "HTTPS-Console", or both, per the user/group’s assigned privileges.

Note that DoD requires users to be assigned to groups rather than assigned privileges to individual users whenever possible.'
  impact 0.5
  ref 'DPMS Target Symantec ProxySG NDM'
  tag check_id: 'C-93865r1_chk'
  tag severity: 'medium'
  tag gid: 'V-94675'
  tag rid: 'SV-104505r1_rule'
  tag stig_id: 'SYMP-NM-000120'
  tag gtitle: 'SRG-APP-000122-NDM-000239'
  tag fix_id: 'F-100793r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001494']
  tag nist: ['AU-9']
end
