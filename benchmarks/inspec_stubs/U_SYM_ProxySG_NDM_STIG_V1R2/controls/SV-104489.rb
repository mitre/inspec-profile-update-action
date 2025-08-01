control 'SV-104489' do
  title 'Symantec ProxySG must be configured to enforce assigned privilege levels for approved administrators when accessing the management console, SSH, and the command line interface (CLI).'
  desc 'A mechanism to detect and prevent unauthorized communication flow must be configured or provided as part of the system design. If management information flow is not enforced based on approved authorizations, the network device may become compromised. Information flow control regulates where management information is allowed to travel within a network device. The flow of all management information must be monitored and controlled so it does not introduce any unacceptable risk to the network device or data. 

Application-specific examples of enforcement occur in systems that employ rule sets or establish configuration settings that restrict information system services or message-filtering capability based on message content (e.g., implementing key word searches or using document characteristics).

Applications providing information flow control must be able to enforce approved authorizations for controlling the flow of management information within the system in accordance with applicable policy.'
  desc 'check', '1. Obtain a list of authorized personnel and IP addresses that should have access to the Web Management Console or CLI.
2. Click Configuration >> Policy >> Visual Policy Manager.
3. Click the "Launch button". 
4. Click the "Admin Access" layer.
5. Verify any users and/or groups listed in the "source" field of each rule have the appropriate Action of either "Allow Read/Write access" or "Allow Read-only Access" per the user/group’s assigned privileges.
6. Verify that the users and/or groups have the Service set to "SSH-Console", "HTTPS-Console", or both, depending on the user/group’s assigned privileges.
7. Ensure the account of last resort is not allowed access via the "SSH-Console" or the "HTTPS-Console", but only via the local console port and CLI.

If the Symantec ProxySG is not configured to enforce assigned privilege levels for approved administrators when accessing the Management Console and the CLI, this is a finding.'
  desc 'fix', '1. Obtain a list of authorized personnel and IP addresses that should have access to the Web Management Console or CLI.
2. Click Configuration >> Policy >> Visual Policy Manager.
3. Click the "Launch" button. 
4. Click the "Admin Access" layer.
5. For every user and/or group listed in the "source" field of each rule, set the Action to either "Allow Read/Write access" or "Allow Read-only Access" per the user/group’s assigned privileges.
6. For every user/group, also set the Service to "SSH-Console", "HTTPS-Console", or both, per the user/group’s assigned privileges.
7. Configure the account of last resort to disallow access via the "SSH-Console" and the "HTTPS-Console". Access is only allowed via the local console port and CLI.

Note that DoD requires users to be assigned to groups rather than assigned privileges to individual users whenever possible.'
  impact 0.5
  ref 'DPMS Target Symantec ProxySG NDM'
  tag check_id: 'C-93849r1_chk'
  tag severity: 'medium'
  tag gid: 'V-94659'
  tag rid: 'SV-104489r1_rule'
  tag stig_id: 'SYMP-NM-000040'
  tag gtitle: 'SRG-APP-000038-NDM-000213'
  tag fix_id: 'F-100777r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
