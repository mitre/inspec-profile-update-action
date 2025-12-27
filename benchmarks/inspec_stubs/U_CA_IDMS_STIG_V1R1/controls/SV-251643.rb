control 'SV-251643' do
  title 'CA IDMS must protect system and user code and storage from corruption by user programs.'
  desc 'Database management systems can maintain separate execution domains for each executing process by assigning each process a separate address space. Each process has a distinct address space so that communication between processes is controlled through the security functions, and one process cannot modify the executing code of another process. Maintaining separate execution domains for executing processes can be achieved, for example, by implementing separate address spaces.'
  desc 'check', 'Log on to IDMS DC system and issue "DCPROFIL". If SYSTEM STORAGE PROTECTED: display is "NO", this is a finding. 

Issue DCMT D PROGRAM pgmname where pgmname is ADSOMAIN, ADSORUN1, and user programs. If "Storage Prot" is "NO", this is a finding.'
  desc 'fix', 'Use the following system generation parameters to enable the use of standard storage protection: 

Set STORAGE KEY parameter of the SYSTEM statement to a value that is not" 9". (The value other than 9 is dependent on how the z/OS parm AllowUserKeyCSA is set).

Set PROTECT/NOPROTECT parameter of the SYSTEM statement to "PROTECT".

Set PROTECT/NOPROTECT parameter of the PROGRAM statement to "PROTECT" for ADSOMAIN, ADSORUN1, and user programs.

Generate and restart the system.'
  impact 0.5
  ref 'DPMS Target CA IDMS'
  tag check_id: 'C-55078r807794_chk'
  tag severity: 'medium'
  tag gid: 'V-251643'
  tag rid: 'SV-251643r807796_rule'
  tag stig_id: 'IDMS-DB-000790'
  tag gtitle: 'SRG-APP-000431-DB-000388'
  tag fix_id: 'F-55032r807795_fix'
  tag 'documentable'
  tag cci: ['CCI-002530']
  tag nist: ['SC-39']
end
