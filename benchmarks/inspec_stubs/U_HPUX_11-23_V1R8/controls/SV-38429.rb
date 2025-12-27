control 'SV-38429' do
  title 'The HP-UX AUDOMON_ARGS attribute must be explicitly initialized.'
  desc 'The minimal set of auditing requirements necessary to collect useful forensics data and provide user help when violations are detected must be configured.'
  desc 'check', "Check the /etc/rc.config.d/auditing file AUDOMON_ARGS settings: 

# cat /etc/rc.config.d/auditing | tr “\\011” “ “ | tr -s “ “ | sed -e 's/^[ \\t]*//' grep -v “#”

The above command should return a single line with the following information: 

AUDOMON_ARGS=“-p 20, -t 1, -w 90”

If “p”, “t”, or “w” flags are not set to “20”, “1”, and “90”, respectively, this is a finding."
  desc 'fix', 'Edit the /etc/rc.config.d/auditing file and insert the following line:

AUDOMON_ARGS=“-p 20, -t 1, -w 90”

Restart auditing:
# /sbin/init.d/auditing stop
# /sbin/init.d/auditing start'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36226r2_chk'
  tag severity: 'medium'
  tag gid: 'V-4290'
  tag rid: 'SV-38429r2_rule'
  tag stig_id: 'GEN000000-HPUX0040'
  tag gtitle: 'GEN000000-HPUX0040'
  tag fix_id: 'F-31485r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECAR-2, ECAR-1, ECAR-3'
  tag cci: ['CCI-000126']
  tag nist: ['AU-2 c']
end
