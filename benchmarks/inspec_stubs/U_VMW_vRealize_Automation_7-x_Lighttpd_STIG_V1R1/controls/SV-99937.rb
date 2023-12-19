control 'SV-99937' do
  title 'The Lighttpd baseline must be maintained.'
  desc 'Without maintenance of a baseline of current Lighttpd software, monitoring for changes cannot be complete and unauthorized changes to the software can go undetected. Changes to Lighttpd could be the result of intentional or unintentional actions.'
  desc 'check', 'Obtain supporting documentation from the ISSO.

Determine if a software baseline is being maintained.

If a baseline is not being maintained, this is a finding.'
  desc 'fix', 'Update the software baseline.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x Lighttpd'
  tag check_id: 'C-88979r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89287'
  tag rid: 'SV-99937r1_rule'
  tag stig_id: 'VRAU-LI-000310'
  tag gtitle: 'SRG-APP-000225-WSR-000074'
  tag fix_id: 'F-96029r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001190']
  tag nist: ['SC-24']
end
