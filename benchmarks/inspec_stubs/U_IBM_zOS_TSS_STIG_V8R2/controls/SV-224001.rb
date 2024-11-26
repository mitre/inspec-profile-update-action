control 'SV-224001' do
  title 'IBM z/OS must specify SMF data options to ensure appropriate activation.'
  desc 'Without establishing when events occurred, it is impossible to establish, correlate, and investigate the events leading up to an outage or attack.

In order to compile an accurate risk assessment and provide forensic analysis, it is essential for security personnel to know when events occurred (date and time).

Associating event types with detected events in the operating system audit logs provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured operating system.

'
  desc 'check', 'Refer to IEASYS00 member in SYS1.PARMLIB Concatenation. Determine proper SMFPRMxx member. 

SUBSYS(STC,EXITS(IEFU29,IEFU83,IEFU84,IEFUJP,IEFUSO),
INTERVAL(SMF,SYNC),NODETAIL)

If the SMF collection options are specified as stated below with exception of those specified in the above NOTEs, this is not a finding. 

The settings for several parameters are critical to the collection process:

ACTIVE Activates the collection of SMF data.

MAXDORM(0500) Specifies the amount of real time that SMF allows data to remain in an SMF buffer before it is written to a recording data set. Value is site defined.

SID Specifies the system ID to be recorded in all SMF records.

SYS(DETAIL) Controls the level of detail recorded.

SYS(INTERVAL) Ensures the periodic recording of data for long running jobs.

SYS Specifies the types and sub types of SMF records that are to be collected. SYS(TYPE) indicates that the supplied list is inclusive (i.e., specifies the record types to be collected). Record types not listed are not collected. SYS(NOTYPE) indicates that the supplied list is exclusive (i.e., specifies those record types not to be collected). Record types listed are not collected. The site may use either form of this parameter to specify SMF record type collection. However, at a minimum, all record types are listed.'
  desc 'fix', 'Ensure that collection options for SMF Data are consistent with options specified below.

Review all SMF recording specifications found in SMFPRMxx members. Ensure that SMF recording options used are consistent with those outlined below.

The settings for several parameters are critical to the collection process:

ACTIVE Activates the collection of SMF data.

MAXDORM(mmss) Specifies the amount of real time that SMF allows data to remain in an SMF buffer before it is written to a recording data set. Use the MAXDORM parameter to minimize the amount of data lost because of system failure. This value is site determined and should be carefully configured.

SID Specifies the system ID to be recorded in all SMF records.

SYS(DETAIL) Controls the level of detail recorded.

SYS(INTERVAL) Ensures the periodic recording of data for long running jobs.

SYS Specifies the types and sub types of SMF records that are to be collected. SYS(TYPE) indicates that the supplied list is inclusive (i.e., specifies the record types to be collected). Record types not listed are not collected. SYS(NOTYPE) indicates that the supplied list is exclusive (i.e., specifies those record types not to be collected). Record types not listed are not collected. The site may use either form of this parameter to specify SMF record type collection. However, at a minimum all record types are listed.'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25674r516402_chk'
  tag severity: 'medium'
  tag gid: 'V-224001'
  tag rid: 'SV-224001r561402_rule'
  tag stig_id: 'TSS0-OS-000050'
  tag gtitle: 'SRG-OS-000038-GPOS-00016'
  tag fix_id: 'F-25662r516403_fix'
  tag satisfies: ['SRG-OS-000038-GPOS-00016', 'SRG-OS-000039-GPOS-00017', 'SRG-OS-000040-GPOS-00018', 'SRG-OS-000041-GPOS-00019', 'SRG-OS-000042-GPOS-00021', 'SRG-OS-000254-GPOS-00095', 'SRG-OS-000269-GPOS-00103', 'SRG-OS-000368-GPOS-00154']
  tag 'documentable'
  tag legacy: ['SV-107813', 'V-98709']
  tag cci: ['CCI-000131', 'CCI-000132', 'CCI-000135', 'CCI-000133', 'CCI-000134', 'CCI-001464', 'CCI-001764', 'CCI-001665']
  tag nist: ['AU-3 b', 'AU-3 c', 'AU-3 (1)', 'AU-3 d', 'AU-3 e', 'AU-14 (1)', 'CM-7 (2)', 'SC-24']
end
