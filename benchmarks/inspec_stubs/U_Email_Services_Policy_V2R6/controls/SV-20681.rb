control 'SV-20681' do
  title 'Email critical software copies must be stored off-site in a fire-rated container.'
  desc 'There is always potential that accidental loss can cause system loss and that restoration will be needed. In the event that the installation site is compromised, damaged or destroyed copies of critical software media may be needed to recover the systems and become operational. 

Copies of the operating system (OS) and other critical software, such as email services applications must be created and stored off-site in a fire-rated container. If a site experiences loss or compromise of the installed software libraries, available copies can reduce the risk and shorten the time period for a successful email services recovery.'
  desc 'check', 'Access the EDSP and review the email application software offline storage plan.  Examine artifacts showing that copies exist and are stored off-site in fire-rated containers.  

If an email software copy exists and is stored off-site in a fire-rated container, this is not a finding.'
  desc 'fix', 'Create email software copies for use in recovering systems, and store them off-site and in fire-rated containers.  Document the off-site storage details in the EDSP.'
  impact 0.5
  ref 'DPMS Target E-mail Services Policy'
  tag check_id: 'C-22538r3_chk'
  tag severity: 'medium'
  tag gid: 'V-18884'
  tag rid: 'SV-20681r3_rule'
  tag stig_id: 'EMG3-010 EMail'
  tag gtitle: 'EMG3-010 Software Critical Copies'
  tag fix_id: 'F-19497r3_fix'
  tag 'documentable'
  tag responsibility: 'Other'
  tag ia_controls: 'COSW-1'
end
