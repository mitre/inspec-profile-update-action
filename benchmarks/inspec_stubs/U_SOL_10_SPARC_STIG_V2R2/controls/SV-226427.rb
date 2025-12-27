control 'SV-226427' do
  title 'The inherit-pkg-dir zone option must be set to none or the system default list defined for sparse root zones.'
  desc "Solaris zones have the capability to inherit elements of the global zone's filesystem, which reduces the amount storage required for a zone, but also limits the flexibility of the zone.  The inherit-pkg-dir option defines which paths are shared between the zones.  If set incorrectly, private information from the global zone could be made available to the non-global zone.  This option must be set to none (for a whole-root non-global zone), the vendor-specified list of paths for sparse-root non-global zones, or a list specified by the SA for operational reasons which has been justified and documented with the IAO."
  desc 'check', 'If the system is not a global zone, this vulnerability is not applicable.
List the non-global zones on the system.
# zoneadm list -vi
List the configuration for each zone.
# zonecfg -z <zone> info
Check the inherit-pkg-dir lines.  If no such lines exist, this is not a finding.  If the lines contain only those defined for sparse root zones (/lib, /platform, /sbin, /usr), this is not a finding.  Otherwise, this is a finding.'
  desc 'fix', 'Remove the inherit-pkg-dir lines or the directories not defined for sparse root zones.
# zonecfg -z <zone> remove inherit-pkg-dir=<somedir>'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28588r482642_chk'
  tag severity: 'medium'
  tag gid: 'V-226427'
  tag rid: 'SV-226427r603265_rule'
  tag stig_id: 'GEN000000-SOL00620'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-28576r482643_fix'
  tag 'documentable'
  tag legacy: ['SV-27022', 'V-22607']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
