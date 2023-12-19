control 'SV-215191' do
  title 'AIX administrative accounts must not run a web browser, except as needed for local service administration.'
  desc "If a web browser flaw is exploited while running as a privileged user, the entire system could be compromised. 

Specific exceptions for local service administration should be documented in site-defined policy. These exceptions may include HTTP(S)-based tools used for the administration of the local system, services, or attached devices. Examples of possible exceptions are HP’s System Management Homepage (SMH), the CUPS administrative interface, and Sun's StorageTek Common Array Manager (CAM) when these services are running on the local system."
  desc 'check', 'Inspect the root account home directory for a ".netscape" or a ".mozilla" directory using the following commands: 
# find /home/root -name .netscape
# find /home/root -name .mozilla

If none exists, this is not a finding. 

If a file exists, verify with the root users and the ISSO the intent of the browsing.

If a file exists and use of a web browser has not been authorized, this is a finding.'
  desc 'fix', 'Enforce policy requiring administrative accounts use web browsers only for local service administration.'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16389r294024_chk'
  tag severity: 'medium'
  tag gid: 'V-215191'
  tag rid: 'SV-215191r508663_rule'
  tag stig_id: 'AIX7-00-001032'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16387r294025_fix'
  tag 'documentable'
  tag legacy: ['V-91607', 'SV-101705']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
