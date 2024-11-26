control 'SV-223977' do
  title 'IBM z/OS FTP Control cards must be properly stored in a secure PDS file.'
  desc 'Configuration settings are the set of parameters that can be changed in hardware, software, or firmware components of the system that affect the security posture and/or functionality of the system. Security-related parameters are those parameters impacting the security state of the system, including the parameters required to satisfy other security control requirements. Security-related parameters include, for example: registry settings; account, file, directory permission settings; and settings for functions, ports, protocols, services, and remote connections.'
  desc 'check', 'Ask the System administrator fora list(s) of the locations for all FTP Control cards within a given application/AIS, ensuring no FTP control cards are within in-stream JCL, JCL libraries or any open access data sets. 

If access to PDS files where FTP Control cards are stored are not restricted to appropriate personnel this is a finding.'
  desc 'fix', 'Make sure that the FTP control Cards for each FTP are stored in a secure PDS and that they are not placed in the JCL libraries or in the in-stream JCL for each FTP.'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25650r516330_chk'
  tag severity: 'medium'
  tag gid: 'V-223977'
  tag rid: 'SV-223977r877818_rule'
  tag stig_id: 'TSS0-FT-000050'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-25638r516331_fix'
  tag 'documentable'
  tag legacy: ['SV-107765', 'V-98661']
  tag cci: ['CCI-000202', 'CCI-000366']
  tag nist: ['IA-5 (7)', 'CM-6 b']
end
