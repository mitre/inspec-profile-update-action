control 'SV-234874' do
  title 'The SUSE operating system must not have unnecessary accounts.'
  desc 'Accounts providing no operational purpose provide additional opportunities for system compromise. Unnecessary accounts include user accounts for individuals not requiring access to the system and application accounts for applications not installed on the system.'
  desc 'check', 'Verify all SUSE operating system accounts are assigned to an active system, application, or user account.

Obtain the list of authorized system accounts from the Information System Security Officer (ISSO).

Check the system accounts on the system with the following command:

> more /etc/passwd
root:x:0:0:root:/root:/bin/bash
...
games:x:12:100:Games account:/var/games:/bin/bash

Accounts such as "games" and "gopher" are not authorized accounts as they do not support authorized system functions. 

If the accounts on the system do not match the provided documentation, this is a finding.'
  desc 'fix', 'Configure the SUSE operating system so all accounts on the system are assigned to an active system, application, or user account. 

Remove accounts that do not support approved system activities or that allow for a normal user to perform administrative-level actions. 

Document all authorized accounts on the system.'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-38062r618891_chk'
  tag severity: 'medium'
  tag gid: 'V-234874'
  tag rid: 'SV-234874r622137_rule'
  tag stig_id: 'SLES-15-020090'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-38025r618892_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
