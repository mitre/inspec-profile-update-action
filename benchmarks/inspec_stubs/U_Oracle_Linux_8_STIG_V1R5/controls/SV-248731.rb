control 'SV-248731' do
  title 'OL 8 must resolve audit information before writing to disk.'
  desc 'Without establishing what type of events occurred and their source, location, and outcome, it would be difficult to establish, correlate, and investigate the events leading up to an outage or attack. 
 
Audit record content that may be necessary to satisfy this requirement includes, for example, time stamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked. 
 
Enriched logging aids in making sense of who, what, and when events occur on a system. Without this, determining root cause of an event will be much more difficult.'
  desc 'check', 'Verify the OL 8 audit daemon is configured to resolve audit information before writing to disk, with the following command: 
 
$ sudo grep "log_format" /etc/audit/auditd.conf 
 
log_format = ENRICHED 
 
If the "log_format" option is not "ENRICHED", or the line is commented out, this is a finding.'
  desc 'fix', 'Configure OL 8 to resolve audit information before writing to disk by adding the following line to the "/etc/audit/auditd.conf" file and add or update the "log_format" option: 
 
log_format = ENRICHED 
 
The audit daemon must be restarted for changes to take effect.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52165r779757_chk'
  tag severity: 'medium'
  tag gid: 'V-248731'
  tag rid: 'SV-248731r779759_rule'
  tag stig_id: 'OL08-00-030063'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-52119r779758_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
