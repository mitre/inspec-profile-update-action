control 'SV-225142' do
  title 'The macOS system must generate audit records for all account creations, modifications, disabling, and termination events; privileged activities or other system-level access; all kernel module load, unload, and restart actions; all program initiations; and organizationally defined events for all non-local maintenance and diagnostic sessions.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. Audit records can be generated from various components within the information system (e.g., module or policy filter). If events associated with nonlocal administrative access or diagnostic sessions are not logged, a major tool for assessing and investigating attacks would not be available.

This requirement addresses auditing-related issues associated with maintenance tools used specifically for diagnostic and repair actions on organizational information systems.

Nonlocal maintenance and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network (e.g., the Internet) or an internal network. Local maintenance and diagnostic activities are those activities carried out by individuals physically present at the information system or information system component and not communicating across a network connection.

This requirement applies to hardware/software diagnostic test equipment or tools. This requirement does not cover hardware/software components that may support information system maintenance, yet are a part of the system, for example, the software implementing "ping," "ls," "ipconfig," or the hardware and software implementing the monitoring port of an Ethernet switch.

'
  desc 'check', 'To view the currently configured flags for the audit daemon, run the following command:

/usr/bin/sudo /usr/bin/grep ^flags /etc/security/audit_control

Administrative and Privileged access, including administrative use of the command line tools "kextload" and "kextunload" and changes to configuration settings are logged by way of the "ad" flag.

If "ad" is not listed in the result of the check, this is a finding.'
  desc 'fix', %q(To ensure the appropriate flags are enabled for auditing, run the following command:

/usr/bin/sudo /usr/bin/sed -i.bak '/^flags/ s/$/,ad/' /etc/security/audit_control; /usr/bin/sudo /usr/sbin/audit -s

A text editor may also be used to implement the required updates to the "/etc/security/audit_control" file.)
  impact 0.5
  ref 'DPMS Target Apple OS X 10.15'
  tag check_id: 'C-26841r467594_chk'
  tag severity: 'medium'
  tag gid: 'V-225142'
  tag rid: 'SV-225142r610901_rule'
  tag stig_id: 'AOSX-15-001001'
  tag gtitle: 'SRG-OS-000004-GPOS-00004'
  tag fix_id: 'F-26829r485759_fix'
  tag satisfies: ['SRG-OS-000004-GPOS-00004', 'SRG-OS-000239-GPOS-00089', 'SRG-OS-000240-GPOS-00090', 'SRG-OS-000241-GPOS-00091', 'SRG-OS-000327-GPOS-00127', 'SRG-OS-000392-GPOS-00172', 'SRG-OS-000471-GPOS-00215', 'SRG-OS-000471-GPOS-00216', 'SRG-OS-000476-GPOS-00221', 'SRG-OS-000477-GPOS-00222']
  tag 'documentable'
  tag legacy: ['V-102701', 'SV-111663']
  tag cci: ['CCI-001403', 'CCI-001404', 'CCI-001405', 'CCI-000018', 'CCI-000172', 'CCI-002234', 'CCI-002884']
  tag nist: ['AC-2 (4)', 'AC-2 (4)', 'AC-2 (4)', 'AC-2 (4)', 'AU-12 c', 'AC-6 (9)', 'MA-4 (1) (a)']
end
