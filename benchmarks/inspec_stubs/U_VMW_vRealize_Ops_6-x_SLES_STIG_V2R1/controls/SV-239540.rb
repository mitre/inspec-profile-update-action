control 'SV-239540' do
  title 'The SMTP service must not have the EXPN feature active.'
  desc 'The SMTP EXPN function allows an attacker to determine if an account exists on a system, providing significant assistance to a brute force attack on user accounts. EXPN may also provide additional information concerning users on the system, such as the full names of account owners.'
  desc 'check', 'Use the following command to check if EXPN is disabled:

# grep -v "^#" /etc/sendmail.cf |grep -i PrivacyOptions

If "noexpn" is not returned, this is a finding.'
  desc 'fix', 'Add "noexpn" to the "PrivacyOptions" flag in the "/etc/sendmail.cf" file.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x SLES'
  tag check_id: 'C-42773r662069_chk'
  tag severity: 'medium'
  tag gid: 'V-239540'
  tag rid: 'SV-239540r662071_rule'
  tag stig_id: 'VROM-SL-000605'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-42732r662070_fix'
  tag 'documentable'
  tag legacy: ['SV-99201', 'V-88551']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
