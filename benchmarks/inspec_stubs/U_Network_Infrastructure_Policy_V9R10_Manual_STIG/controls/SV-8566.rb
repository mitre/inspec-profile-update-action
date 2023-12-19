control 'SV-8566' do
  title 'The Intrusion Detection and Prevention System (IDPS) software and signatures must be updated when updates are provided by the vendor.'
  desc 'Keeping the IDPS software updated with the latest engine and attack signatures will allow for the IDPS to detect all forms of known attacks.  Not maintaining the IDPS properly could allow for attacks to go unnoticed.'
  desc 'check', 'Interview the ISSO and the IDPS administrator. Have the IDPS administrator display update notifications that have been received, the build number or patch level, then search the vendor’s vulnerability database for current release and patch level.

If software and signatures are not updated when updates are provided by the vendor, this is a finding.'
  desc 'fix', 'Have the IDPS administrator subscribe to the X-press notification or similar service offered by the vendor. Ensure the IDPS software is updated when software is available either by DISA or the vendor for security related distributions.'
  impact 0.3
  ref 'DPMS Target Network Infrastructure Policy'
  tag check_id: 'C-7461r2_chk'
  tag severity: 'low'
  tag gid: 'V-8080'
  tag rid: 'SV-8566r2_rule'
  tag stig_id: 'NET-IDPS-035'
  tag gtitle: 'SA has not subscribed to the vendor notifications.'
  tag fix_id: 'F-7655r3_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
