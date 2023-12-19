control 'SV-221667' do
  title 'The Oracle Linux operating system must be configured so that /etc/pam.d/passwd implements /etc/pam.d/system-auth when changing passwords.'
  desc 'Pluggable authentication modules (PAM) allow for a modular approach to integrating authentication methods. PAM operates in a top-down processing model and if the modules are not listed in the correct order, an important security function could be bypassed if stack entries are not centralized.'
  desc 'check', 'Verify that /etc/pam.d/passwd is configured to use /etc/pam.d/system-auth when changing passwords:

# cat /etc/pam.d/passwd | grep -i substack | grep -i system-auth
password substack system-auth

If no results are returned, the line is commented out, this is a finding.'
  desc 'fix', 'Configure PAM to utilize /etc/pam.d/system-auth when changing passwords.

Add the following line to "/etc/pam.d/passwd" (or modify the line to have the required value):

password substack system-auth'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23382r419073_chk'
  tag severity: 'medium'
  tag gid: 'V-221667'
  tag rid: 'SV-221667r603260_rule'
  tag stig_id: 'OL07-00-010118'
  tag gtitle: 'SRG-OS-000069-GPOS-00037'
  tag fix_id: 'F-23371r419074_fix'
  tag 'documentable'
  tag legacy: ['SV-108179', 'V-99075']
  tag cci: ['CCI-000192']
  tag nist: ['IA-5 (1) (a)']
end
