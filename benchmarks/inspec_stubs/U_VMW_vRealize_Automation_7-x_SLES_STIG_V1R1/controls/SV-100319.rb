control 'SV-100319' do
  title 'The SMTP service must not have the EXPN feature active.'
  desc 'The SMTP EXPN function allows an attacker to determine if an account exists on a system, providing significant assistance to a brute force attack on user accounts. EXPN may also provide additional information concerning users on the system, such as the full names of account owners.'
  desc 'check', 'Use the following command to check if EXPN is disabled:

# grep -v "^#" /etc/sendmail.cf |grep -i PrivacyOptions

If "noexpn" is not returned, this is a finding.'
  desc 'fix', 'Add "noexpn" to the "PrivacyOptions" flag in /etc/sendmail.cf'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x SLES'
  tag check_id: 'C-89361r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89669'
  tag rid: 'SV-100319r1_rule'
  tag stig_id: 'VRAU-SL-000625'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-96411r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
