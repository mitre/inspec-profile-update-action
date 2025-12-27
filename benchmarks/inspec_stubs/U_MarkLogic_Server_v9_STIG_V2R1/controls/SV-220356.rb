control 'SV-220356' do
  title 'MarkLogic Server software installation account must be restricted to authorized users.'
  desc 'When dealing with change control issues, it should be noted any changes to the hardware, software, and/or firmware components of the information system and/or application could have significant effects on the overall security of the system. 

If the system were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

Accordingly, only qualified and authorized individuals must be allowed access to information system components for purposes of initiating changes, including upgrades and modifications.

DBA and other privileged administrative or application owner accounts are granted privileges that allow actions that can have a great impact on database security and operation. It is especially important to grant privileged access to only those persons who are qualified and authorized to use them.'
  desc 'check', 'Review procedures for controlling, granting access to, and tracking use of the MarkLogic software installation account.

If access or use of this account is not restricted to the minimum number of personnel required or if unauthorized access to the account has been granted, this is a finding.

At a command prompt, on the system where MarkLogic is installed run the following command:
> ls -al /var/opt/MarkLogic 

If files are owned by the user "daemon", this is not a finding.

If user is not "daemon", verify that Organization policy and system documentation states that a separate user is needed and approved.'
  desc 'fix', 'Review procedures for controlling, granting access to, and tracking the use of the MarkLogic software installation account.

Ensure use of this account is restricted to the minimum number of personnel required and no unauthorized access to the account has been granted.

MarkLogic should be installed by a user account that has "sudo" privileges to run "yum" or "rpm". At a command prompt, on the system where MarkLogic is installed, run one of the following commands:
> sudo yum install /path/to/MarkLogic-version.rpm 
or
> sudo rpm -i /path/to/MarkLogic-version.rpm

Either of these commands will install MarkLogic with the owner set correctly to "daemon".

If user is not "daemon", ensure Organization policy and system documentation states that a separate user is needed and approved.'
  impact 0.5
  ref 'DPMS Target MarkLogic Server v9'
  tag check_id: 'C-22071r401519_chk'
  tag severity: 'medium'
  tag gid: 'V-220356'
  tag rid: 'SV-220356r622777_rule'
  tag stig_id: 'ML09-00-002600'
  tag gtitle: 'SRG-APP-000133-DB-000198'
  tag fix_id: 'F-22060r401520_fix'
  tag 'documentable'
  tag legacy: ['SV-110059', 'V-100955']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
