control 'SV-33061' do
  title 'Installation of a compiler on production web server must be prohibited.'
  desc 'The presence of a compiler on a production server facilitates the malicious user’s task of creating custom versions of programs and installing Trojan Horses or viruses. For example, the attacker’s code can be uploaded and compiled on the server under attack.'
  desc 'check', 'Using Windows Explorer, search the system for the existence of known compilers such as msc.exe, msvc.exe, Python.exe, javac.exe, Lcc-win32.exe, or equivalent. Look in all hard drives. 

Also, query the SA and the Web Manager to determine if a compiler is present on the server. 

Query the SA and the Web Manager to determine if a compiler is present on the server.  If a compiler is present, this is a finding.

NOTE:  When Apache is part of a suite install, e.g. application server, and a compiler is needed for installation and patching of the product, document the installation of the compiler with the ISSO/ISSM and verify that the compiler is restricted to administrative users only.  If documented and restricted to administrative users, this is not a finding.'
  desc 'fix', 'Remove any compiler found on the production web server.  If the compiler is needed to patch the product in a production environment, document the compiler installation with the ISSO/ISSM and ensure that the compiler is restricted to only administrative users.'
  impact 0.5
  ref 'DPMS Target Apache Instance 2.x'
  tag check_id: 'C-33733r3_chk'
  tag severity: 'medium'
  tag gid: 'V-2236'
  tag rid: 'SV-33061r3_rule'
  tag stig_id: 'WG080 W22'
  tag gtitle: 'WG080'
  tag fix_id: 'F-29368r3_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
end
