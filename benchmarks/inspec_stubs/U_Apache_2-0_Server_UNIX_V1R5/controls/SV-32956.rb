control 'SV-32956' do
  title 'Installation of a compiler on production web server is prohibited.'
  desc 'The presence of a compiler on a production server facilitates the malicious user’s task of creating custom versions of programs and installing Trojan Horses or viruses. For example, the attacker’s code can be uploaded and compiled on the server under attack.'
  desc 'check', "Query the SA and the Web Manager to determine if a compiler is present on the server.  If a compiler is present, this is a finding. 

NOTE:  If the web server is part of an application suite and a compiler is needed for installation, patching, and upgrading of the suite or if the compiler is embedded and can't be removed without breaking the suite, document the installation of the compiler with the ISSO/ISSM and verify that the compiler is restricted to administrative users only.  If documented and restricted to administrative users, this is not a finding."
  desc 'fix', 'Remove any compiler found on the production web server, but if the compiler program is needed to patch or upgrade an application suite in a production environment or the compiler is embedded and will break the suite if removed, document the compiler installation with the ISSO/ISSM and ensure that the compiler is restricted to only administrative users.'
  impact 0.5
  ref 'DPMS Target Apache Instance 2.0'
  tag check_id: 'C-33638r4_chk'
  tag severity: 'medium'
  tag gid: 'V-2236'
  tag rid: 'SV-32956r3_rule'
  tag stig_id: 'WG080 A22'
  tag gtitle: 'WG080'
  tag fix_id: 'F-29279r4_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
  tag ia_controls: 'ECSC-1'
end
