control 'SV-240067' do
  title 'The HAProxy baseline must be documented and maintained.'
  desc 'Without maintenance of a baseline of current HAProxy software, monitoring for changes cannot be complete and unauthorized changes to the software can go undetected. Changes to HAProxy could be the result of intentional or unintentional actions.'
  desc 'check', 'Have the appliance administrator and/or ISSO provide the HAProxy software baseline procedures, implementation evidence, and a list of files and directories included in the baseline procedure for completeness.

If baseline procedures do not exist, not implemented reliably, or are not complete, this is a finding.'
  desc 'fix', 'Develop, document, and implement baseline procedures that include all HAProxy software files and directories.

Update the baseline after new installations, upgrades, or maintenance activities that include changes to the software baseline.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x HA Proxy'
  tag check_id: 'C-43300r665368_chk'
  tag severity: 'medium'
  tag gid: 'V-240067'
  tag rid: 'SV-240067r879640_rule'
  tag stig_id: 'VRAU-HA-000275'
  tag gtitle: 'SRG-APP-000225-WSR-000074'
  tag fix_id: 'F-43259r665369_fix'
  tag 'documentable'
  tag legacy: ['SV-99821', 'V-89171']
  tag cci: ['CCI-001190']
  tag nist: ['SC-24']
end
