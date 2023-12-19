control 'SV-32632' do
  title 'Installation of compilers on production web servers is prohibited.'
  desc 'The presence of a compiler on a production server facilitates the malicious user’s task of creating custom versions of programs and installing Trojan Horses or viruses.'
  desc 'check', "Using Windows Explorer and/or add-remove programs, search the system for the existence of known compilers, such as, msc.exe, msvc.exe, Python.exe, javac.exe, Lcc-win32.exe, or equivalent.

If a compiler is found on the production server, this is a finding.

NOTE:  If the web server is part of an application suite and a compiler is needed for installation, patching, and upgrading of the suite or if the compiler is embedded and can't be removed without breaking the suite, document the installation of the compiler with the ISSO/ISSM and verify that the compiler is restricted to administrative users only.  If documented and restricted to administrative users, this is not a finding."
  desc 'fix', 'Remove any compiler found on the production web server, but if the compiler program is needed to patch or upgrade an application suite in a production environment or the compiler is embedded and will break the suite if removed, document the compiler installation with the ISSO/ISSM and ensure that the compiler is restricted to only administrative users.'
  impact 0.5
  ref 'DPMS Target IIS Installation 7'
  tag check_id: 'C-33494r4_chk'
  tag severity: 'medium'
  tag gid: 'V-2236'
  tag rid: 'SV-32632r4_rule'
  tag stig_id: 'WG080 IIS7'
  tag gtitle: 'WG080'
  tag fix_id: 'F-26803r4_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
end
