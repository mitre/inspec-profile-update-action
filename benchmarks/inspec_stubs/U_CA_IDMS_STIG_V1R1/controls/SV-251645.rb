control 'SV-251645' do
  title 'The system storage used for data collection by the CA IDMS server must be protected.'
  desc 'Information can be either unintentionally or maliciously disclosed or modified during preparation for transmission, including, for example, during aggregation, at protocol transformation points, and during packing/unpacking. These unauthorized disclosures or modifications compromise the confidentiality or integrity of the information.

Use of this requirement will be limited to situations where the data owner has a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process. 

When transmitting data, the DBMS, associated applications, and infrastructure must leverage transmission protection mechanisms.

'
  desc 'check', 'Log on to IDMS DC system and issue DCPROFIL. 

If HPSPO ENABLED: display is "NO", this is a finding.'
  desc 'fix', 'Use the following system generation parameters to enable the use of high performance storage protection:

Set STORAGE KEY parameter of the SYSTEM statement to "9".

Set PROTECT/NOPROTECT parameter of the SYSTEM statement to "PROTECT".

Set PROTECT/NOPROTECT parameter of the PROGRAM statement to "PROTECT" for PROGRAMS required to run with the alternate protect key (i.e., 9).

DCMT DISPLAY ALL STORAGE POOLS can be used to take note of what pools support any type of user storage; that is, user, user-kept, shared, shared-kept, or ALL, in preparation for the next step.

If necessary, redefine storage pools so all forms of user-oriented storage (user, user-kept, shared, and shared-kept) are segregated from the system storage (database, terminal). For example:
ADD STORAGE POOL 1
CONTAINS TYPES ( SHARED SHARED-KEPT USER USER-KEPT )
ADD XA STORAGE POOL 128
CONTAINS TYPES ( USER USER-KEPT )
ADD XA STORAGE POOL 129
CONTAINS TYPES ( SHARED SHARED-KEPT )
ADD XA STORAGE POOL 130
CONTAINS TYPES ( TERMINAL DATABASE )

Generate and start the system. The storage pool definitions have been set up correctly if the message "DC004001 HPSPO HAS BEEN DISABLED DUE TO INCORRECT STORAGE POOL DEFINITIONS" is not issued at startup.'
  impact 0.5
  ref 'DPMS Target CA IDMS'
  tag check_id: 'C-55080r807800_chk'
  tag severity: 'medium'
  tag gid: 'V-251645'
  tag rid: 'SV-251645r807802_rule'
  tag stig_id: 'IDMS-DB-000810'
  tag gtitle: 'SRG-APP-000441-DB-000378'
  tag fix_id: 'F-55034r807801_fix'
  tag satisfies: ['SRG-APP-000441-DB-000378', 'SRG-APP-000442-DB-000379']
  tag 'documentable'
  tag cci: ['CCI-002420', 'CCI-002422']
  tag nist: ['SC-8 (2)', 'SC-8 (2)']
end
