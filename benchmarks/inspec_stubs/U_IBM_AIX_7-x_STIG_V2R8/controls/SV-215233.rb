control 'SV-215233' do
  title 'AIX must be able to control the ability of remote login for users.'
  desc 'Remote access services, such as those providing remote access to network devices and information systems, which lack automated control capabilities, increase risk and make remote user access management difficult at best.

Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Operating system functionality (e.g., RDP) must be capable of taking enforcement action if the audit reveals unauthorized activity. Automated control of remote access sessions allows organizations to ensure ongoing compliance with remote access policies by enforcing connection rules of remote access applications on a variety of information system components (e.g., servers, workstations, notebook computers, smartphones, and tablets).'
  desc 'check', 'For users who are authorized to remote login through SSH, etc., this is Not Applicable.

Ask ISSO/SA to obtain a list of users who are not authorized to remotely log in to AIX system.

From the command prompt, run the following command to check if remote login is disabled for all individual users who are not authorized to remotely login to AIX:
# lsuser -a rlogin ALL
root rlogin=true
daemon rlogin=true
bin rlogin=true
sys rlogin=true
adm rlogin=true

If "rlogin=true" for any user who should not login remotely, this is a finding.'
  desc 'fix', 'From the command prompt, run the following command to set "rlogin=false" for all users (user_name) who are not authorized to login remotely:
# chsec -f /etc/security/user -s [user_name] -a rlogin=false'
  impact 0.7
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16431r294150_chk'
  tag severity: 'high'
  tag gid: 'V-215233'
  tag rid: 'SV-215233r853459_rule'
  tag stig_id: 'AIX7-00-001137'
  tag gtitle: 'SRG-OS-000297-GPOS-00115'
  tag fix_id: 'F-16429r294151_fix'
  tag 'documentable'
  tag legacy: ['SV-101601', 'V-91503']
  tag cci: ['CCI-002314']
  tag nist: ['AC-17 (1)']
end
