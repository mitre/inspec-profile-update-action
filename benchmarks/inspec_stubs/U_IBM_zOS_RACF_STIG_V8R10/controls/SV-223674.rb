control 'SV-223674' do
  title 'IBM RACF must limit Write or greater access to SYS1.IMAGELIB to system programmers only.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

'
  desc 'check', 'Execute a dataset list of access for SYS1.IMAGELIB.

If the following guidance is true, this is not a finding.

-The ACP data set rules for SYS1.IMAGELIB do not restrict WRITER or greater access to only systems programming personnel.
-The ACP data set rules for SYS1.IMAGELIB do not specify that all (i.e., failures and successes) WRITER or greater access will be logged.'
  desc 'fix', 'Configure UPDATE and/or ALLOCATE access to SYS1.IMAGELIB to be limited to system programmers only and all WRITE or greater access is logged.

Review access authorization to critical system files. Evaluate the impact of correcting the deficiency. Develop a plan of action and implement the changes as required to protect SYS1.IMAGELIB.

SYS1.IMAGELIB is automatically APF-authorized. This data set contains modules, images, tables, and character sets which are essential to system print services.'
  impact 0.7
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25347r514711_chk'
  tag severity: 'high'
  tag gid: 'V-223674'
  tag rid: 'SV-223674r604139_rule'
  tag stig_id: 'RACF-ES-000260'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25335r514712_fix'
  tag satisfies: ['SRG-OS-000080-GPOS-00048', 'SRG-OS-000259-GPOS-00100']
  tag 'documentable'
  tag legacy: ['SV-107157', 'V-98053']
  tag cci: ['CCI-000213', 'CCI-001499']
  tag nist: ['AC-3', 'CM-5 (6)']
end
