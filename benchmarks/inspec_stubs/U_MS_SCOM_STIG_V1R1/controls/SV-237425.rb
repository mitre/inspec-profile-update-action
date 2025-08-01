control 'SV-237425' do
  title 'SCOM Run As accounts used to manage Linux/UNIX endpoints must be configured for least privilege.'
  desc 'The Microsoft SCOM privileged Run As accounts are used to execute work flow tasks on target endpoints. A SCOM Run As account must only have the level of privileges required to perform the defined SCOM actions. An account with full administrative (SUDO) privileges could be used to breach security boundaries and compromise the endpoint.'
  desc 'check', 'If the Microsoft SCOM environment is not used to monitor Linux/UNIX endpoints, this check is Not Applicable.

Review the account permission settings on the SCOM Management server.

Log on to a subset of Linux or UNIX servers being monitored by SCOM and look at the Sudoers file. Verify that the SCOM account does not have Sudo all permissions. Alternatively, the following command can be run from the machine "sudo -l -U <Run As account Name>".

If any Run As account used for Linux\\UNIX endpoint management has the SUDO ALL permissions, this is a finding.'
  desc 'fix', "Configure the permissions on the Run As accounts used on Linux/UNIX endpoints to remove the SUDO ALL permissions. This will be dependent on the specific versions and flavor of the Linux/UNIX operating systems in question. 

Microsoft's least privilege recommendations for supported versions can be found at the following location: https://social.technet.microsoft.com/wiki/contents/articles/7375.scom-configuring-sudo-elevation-for-UNIX-and-linux-monitoring.aspx."
  impact 0.7
  ref 'DPMS Target Microsoft SCOM'
  tag check_id: 'C-40644r643919_chk'
  tag severity: 'high'
  tag gid: 'V-237425'
  tag rid: 'SV-237425r643921_rule'
  tag stig_id: 'SCOM-AC-000003'
  tag gtitle: 'SRG-APP-000033-NDM-000212'
  tag fix_id: 'F-40607r643920_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
