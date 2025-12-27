control 'SV-100321' do
  title 'The SMTP service must not have the VRFY feature active.'
  desc 'The VRFY (Verify) command allows an attacker to determine if an account exists on a system, providing significant assistance to a brute force attack on user accounts. VRFY may provide additional information about users on the system, such as the full names of account owners.'
  desc 'check', 'Use the following command to check if VRFY is disabled:

# grep -v "^#" /etc/sendmail.cf |grep -i PrivacyOptions

If "novrfy" is not returned, this is a finding.'
  desc 'fix', 'Add "novrfy" to the "PrivacyOptions" flag in /etc/sendmail.cf'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x SLES'
  tag check_id: 'C-89363r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89671'
  tag rid: 'SV-100321r1_rule'
  tag stig_id: 'VRAU-SL-000630'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-96413r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
