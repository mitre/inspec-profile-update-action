control 'SV-36498' do
  title 'The web server must use a vendor-supported version of the web server software.'
  desc 'The web server Software, Apache 2.0, is no longer supported for security updates and is not evaluated or updated for vulnerabilities, leaving it open to potential attack. Organizations must transition to a supported Apache release to ensure continued support.'
  desc 'check', 'Apache 2.0 reached end of life on July 9, 2014. If Apache 2.0 is installed on a system, this is a finding.'
  desc 'fix', 'Upgrade Apache to a supported version.'
  impact 0.7
  ref 'DPMS Target Apache Instance 2.0'
  tag check_id: 'C-35600r2_chk'
  tag severity: 'high'
  tag gid: 'V-2246'
  tag rid: 'SV-36498r2_rule'
  tag stig_id: 'WG190 W20'
  tag gtitle: 'WG190'
  tag fix_id: 'F-30834r2_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
  tag ia_controls: 'ECSC-1'
end
