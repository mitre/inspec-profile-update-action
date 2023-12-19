control 'SV-215178' do
  title 'Direct logins to the AIX system must not be permitted to shared accounts, default accounts, application accounts, and utility accounts.'
  desc 'Shared accounts (accounts where two or more people log in with the same user identification) do not provide identification and authentication. There is no way to provide for non-repudiation or individual accountability.'
  desc 'check', 'Obtain a list of Shared/Application/Default/Utility accounts from the ISSO/ISSM.

Shared/Application/Default/Utility accounts can have direct login disabled by setting the "rlogin" parameter to "false" in the user’s stanza of the "/etc/security/user" file. 

From the command prompt, run the following command to check if shared account has "rlogin=true":

# lsuser -a rlogin [shared_account] 
<shared_account> rlogin=true

If a shared account is configured for "rlogin=true", this is a finding.'
  desc 'fix', 'Direct login to shared or application accounts can be prevented by setting the "rlogin=false" in the accounts stanza of the "/etc/security/user" file.

From the command prompt, run the following command to set "rlogin=false" for a shared account:

# chuser rlogin=false [shared_account]'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16376r293985_chk'
  tag severity: 'medium'
  tag gid: 'V-215178'
  tag rid: 'SV-215178r508663_rule'
  tag stig_id: 'AIX7-00-001011'
  tag gtitle: 'SRG-OS-000109-GPOS-00056'
  tag fix_id: 'F-16374r293986_fix'
  tag 'documentable'
  tag legacy: ['SV-101525', 'V-91427']
  tag cci: ['CCI-000770']
  tag nist: ['IA-2 (5)']
end
