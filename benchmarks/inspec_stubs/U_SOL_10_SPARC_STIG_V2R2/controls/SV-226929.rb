control 'SV-226929' do
  title 'Administrative accounts must not run a web browser, except as needed for local service administration.'
  desc "If a web browser flaw is exploited while running as a privileged user, the entire system could be compromised.

Specific exceptions for local service administration should be documented in site-defined policy.  These exceptions may include HTTP(S)-based tools used for the administration of the local system, services, or attached devices.  Examples of possible exceptions are HP's System Management Homepage (SMH), the CUPS administrative interface, and Sun's StorageTek Common Array Manager (CAM) when these services are running on the local system."
  desc 'check', 'Look in the root account home directory for a .netscape  or a .mozilla directory.  If none exists, this is not a finding.  If there is one, verify with the root users and the IAO what the intent of the browsing is.  Some evidence may be obtained by using the browser to view cached pages under the .netscape directory.'
  desc 'fix', 'Enforce policy requiring administrative accounts use web browsers only for local service administration.'
  impact 0.7
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-36406r602821_chk'
  tag severity: 'high'
  tag gid: 'V-226929'
  tag rid: 'SV-226929r603265_rule'
  tag stig_id: 'GEN004220'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-36370r602822_fix'
  tag 'documentable'
  tag legacy: ['V-4382', 'SV-4382']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
