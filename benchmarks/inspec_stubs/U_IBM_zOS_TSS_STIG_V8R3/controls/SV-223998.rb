control 'SV-223998' do
  title 'IBM z/OS required SMF data record types must be collected.'
  desc 'Once an attacker establishes access to a system, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to create an account. Auditing account creation actions provides logging that can be used for forensic purposes.

To address access requirements, many operating systems may be integrated with enterprise level authentication/access/auditing mechanisms that meet or exceed access control policy requirements.

'
  desc 'check', 'Refer to IEASYS00 member in SYS1.PARMLIB Concatenation. Determine proper SMFPRMxx member.

If all of the required SMF record types identified below are collected, this is not a finding.

IBM SMF Records to be collected at a minimum:

0 (00) – IPL
6 (06) – External Writer/ JES Output Writer/ Print Services Facility (PSF)
7 (07) – [SMF] Data Lost
14 (0E) – INPUT or RDBACK Data Set Activity
15 (0F) – OUTPUT, UPDAT, INOUT, or OUTIN Data Set Activity
17 (11) – Scratch Data Set Status
18 (12) – Rename Non-VSAM Data Set Status
24 (18) – JES2 Spool Offload
25 (19) – JES3 Device Allocation
26 (1A) – JES Job Purge
30 (1E) – Common Address Space Work
32 (20) – TSO/E User Work Accounting
41 (29) – DIV Objects and VLF Statistics 
42 (2A) – DFSMS statistics and configuration 
43 (2B) – JES Start
45 (2D) – JES Withdrawal/Stop
47 (2F) – JES SIGNON/Start Line (BSC)/LOGON
48 (30) – JES SIGNOFF/Stop Line (BSC)/LOGOFF
49 (31) – JES Integrity
52 (34) – JES2 LOGON/Start Line (SNA)
53 (35) – JES2 LOGOFF/Stop Line (SNA)
54 (36) – JES2 Integrity (SNA)
55 (37) – JES2 Network SIGNON
56 (38) – JES2 Network Integrity
57 (39) – JES2 Network SYSOUT Transmission
58 (3A) – JES2 Network SIGNOFF
60 (3C) – VSAM Volume Data Set Updated
61 (3D) – Integrated Catalog Facility Define Activity
62 (3E) – VSAM Component or Cluster Opened
64 (40) – VSAM Component or Cluster Status
65 (41) – Integrated Catalog Facility Delete Activity
66 (42) – Integrated Catalog Facility Alter Activity
80 (50) – RACF/TOP SECRET Processing
81 (51) – RACF Initialization
82 (52) - ICSF Statistics
83 (53) – RACF Audit Record For Data Sets
90 (5A) – System Status
92 (5C) except subtypes 10, 11 – OpenMVS File System Activity
102 (66) – DATABASE 2 Performance 
103 (67) – IBM HTTP Server
110 (6E) – CICS/ESA Statistics
118 (76) – TCP/IP Statistics
119 (77) – TCP/IP Statistics 
199 (C7) – TSOMON
230 (E6) – ACF2 or as specified in ACFFDR (vendor-supplied default is 230)
231 (E7) – TSS logs security events under this record type'
  desc 'fix', 'Ensure that SMF recording options are consistent with those outlined below.

IBM SMF Records to be collected at a minimum:

0 (00) – IPL
6 (06) – External Writer/ JES Output Writer/ Print Services Facility (PSF)
7 (07) – [SMF] Data Lost
14 (0E) – INPUT or RDBACK Data Set Activity
15 (0F) – OUTPUT, UPDAT, INOUT, or OUTIN Data Set Activity
17 (11) – Scratch Data Set Status
18 (12) – Rename Non-VSAM Data Set Status
24 (18) – JES2 Spool Offload
25 (19) – JES3 Device Allocation
26 (1A) – JES Job Purge
30 (1E) – Common Address Space Work
32 (20) – TSO/E User Work Accounting
41 (29) – DIV Objects and VLF Statistics 
42 (2A) – DFSMS statistics and configuration 
43 (2B) – JES Start
45 (2D) – JES Withdrawal/Stop
47 (2F) – JES SIGNON/Start Line (BSC)/LOGON
48 (30) – JES SIGNOFF/Stop Line (BSC)/LOGOFF
49 (31) – JES Integrity
52 (34) – JES2 LOGON/Start Line (SNA)
53 (35) – JES2 LOGOFF/Stop Line (SNA)
54 (36) – JES2 Integrity (SNA)
55 (37) – JES2 Network SIGNON
56 (38) – JES2 Network Integrity
57 (39) – JES2 Network SYSOUT Transmission
58 (3A) – JES2 Network SIGNOFF
60 (3C) – VSAM Volume Data Set Updated
61 (3D) – Integrated Catalog Facility Define Activity
62 (3E) – VSAM Component or Cluster Opened
64 (40) – VSAM Component or Cluster Status
65 (41) – Integrated Catalog Facility Delete Activity
66 (42) – Integrated Catalog Facility Alter Activity
80 (50) – RACF/TOP SECRET Processing
81 (51) – RACF Initialization
82 (52) - ICSF Statistics
83 (53) – RACF Audit Record For Data Sets
90 (5A) – System Status
92 (5C) except subtypes 10, 11 – OpenMVS File System Activity
102 (66) – DATABASE 2 Performance 
103 (67) – IBM HTTP Server
110 (6E) – CICS/ESA Statistics
118 (76) – TCP/IP Statistics
119 (77) – TCP/IP Statistics 
199 (C7) – TSOMON
230 (E6) – ACF2 or as specified in ACFFDR (vendor-supplied default is 230)
231 (E7) – TSS logs security events under this record type'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25671r767112_chk'
  tag severity: 'medium'
  tag gid: 'V-223998'
  tag rid: 'SV-223998r767114_rule'
  tag stig_id: 'TSS0-OS-000020'
  tag gtitle: 'SRG-OS-000004-GPOS-00004'
  tag fix_id: 'F-25659r767113_fix'
  tag satisfies: ['SRG-OS-000004-GPOS-00004', 'SRG-OS-000037-GPOS-00015', 'SRG-OS-000038-GPOS-00016', 'SRG-OS-000039-GPOS-00017', 'SRG-OS-000040-GPOS-00018', 'SRG-OS-000041-GPOS-00019', 'SRG-OS-000042-GPOS-00021', 'SRG-OS-000064-GPOS-00033', 'SRG-OS-000458-GPOS-00203', 'SRG-OS-000461-GPOS-00205', 'SRG-OS-000462-GPOS-00206', 'SRG-OS-000463-GPOS-00207', 'SRG-OS-000465-GPOS-00209', 'SRG-OS-000466-GPOS-00210', 'SRG-OS-000467-GPOS-00211', 'SRG-OS-000468-GPOS-00212', 'SRG-OS-000470-GPOS-00214', 'SRG-OS-000471-GPOS-00215', 'SRG-OS-000471-GPOS-00215', 'SRG-OS-000471-GPOS-00216', 'SRG-OS-000472-GPOS-00217', 'SRG-OS-000473-GPOS-00218', 'SRG-OS-000474-GPOS-00219', 'SRG-OS-000475-GPOS-00220', 'SRG-OS-000476-GPOS-00221', 'SRG-OS-000477-GPOS-00222', 'SRG-OS-000239-GPOS-00089', 'SRG-OS-000240-GPOS-00090', 'SRG-OS-000241-GPOS-00091', 'SRG-OS-000255-GPOS-00096', 'SRG-OS-000365-GPOS-00152', 'SRG-OS-000348-GPOS-00136', 'SRG-OS-000303-GPOS-00120', 'SRG-OS-000327-GPOS-00127', 'SRG-OS-000392-GPOS-00172']
  tag 'documentable'
  tag legacy: ['SV-107807', 'V-98703']
  tag cci: ['CCI-000018', 'CCI-000130', 'CCI-000131', 'CCI-000132', 'CCI-000133', 'CCI-000134', 'CCI-000135', 'CCI-000172', 'CCI-001403', 'CCI-001404', 'CCI-001405', 'CCI-001487', 'CCI-001814', 'CCI-001875', 'CCI-002130', 'CCI-002234', 'CCI-002884']
  tag nist: ['AC-2 (4)', 'AU-3 a', 'AU-3 b', 'AU-3 c', 'AU-3 d', 'AU-3 e', 'AU-3 (1)', 'AU-12 c', 'AC-2 (4)', 'AC-2 (4)', 'AC-2 (4)', 'AU-3 f', 'CM-5 (1)', 'AU-7 a', 'AC-2 (4)', 'AC-6 (9)', 'MA-4 (1) (a)']
end
