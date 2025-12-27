control 'SV-217261' do
  title 'The SUSE operating system must be configured to prohibit or restrict the use of functions, ports, protocols, and/or services as defined in the Ports, Protocols, and Services Management (PPSM) Category Assignments List (CAL) and vulnerability assessments.'
  desc 'To prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports/protocols on information systems.

SUSE operating systems are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., VPN and IPS); however, doing so increases risk over limiting the services provided by any one component.

To support the requirements and principles of least functionality, the SUSE operating system must support the organizational requirements, providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved to conduct official business or address authorized quality-of-life issues.

'
  desc 'check', 'Verify the SUSE operating system is configured to prohibit or restrict the use of functions, ports, protocols, and/or services as defined in the Ports, Protocols, and Services Management (PPSM) Category Assignments List (CAL) and vulnerability assessments.

Check that the "SuSEfirewall2.service" is enabled and running by running the following command:

# systemctl status SuSEfirewall2.service
* SuSEfirewall2.service - SuSEfirewall2 phase 2
Loaded: loaded (/usr/lib/systemd/system/SuSEfirewall2.service; enabled; vendor preset: disabled)
Active: active (exited) since Thu 2017-03-09 17:33:29 UTC; 6 days ago
Main PID: 2533 (code=exited, status=0/SUCCESS)
Tasks: 0 (limit: 512)
Memory: 0B
CPU: 0
CGroup: /system.slice/SuSEfirewall2.service

If the service is not enabled, this is a finding.

If the service is not active, this is a finding.

Check the firewall configuration for any unnecessary or prohibited functions, ports, protocols, and/or services by running the following command:

# grep ^FW_ /etc/sysconfig/SuSEfirewall2

Ask the System Administrator for the site or program PPSM Component Local Services Assessment (Component Local Services Assessment (CLSA). Verify the services allowed by the firewall match the PPSM CLSA. 

If there are any additional ports, protocols, or services that are not included in the PPSM CLSA, this is a finding.

If there are any ports, protocols, or services that are prohibited by the PPSM CAL, this is a finding.'
  desc 'fix', 'Configure the SUSE operating system is configured to prohibit or restrict the use of functions, ports, protocols, and/or services as defined in the Ports, Protocols, and Services Management (PPSM) Category Assignments List (CAL) and vulnerability assessments.

Add/modify /etc/sysconfig/SuSEfirewall2 file to comply with the Ports, Protocols, and Services Management (PPSM) Category Assignments List (CAL).

Enable the "SuSEfirewall2.service" by running the following command:

# systemctl enable SuSEfirewall2.service

Start the "SuSEfirewall2.service" by running the following command:

# systemctl start SuSEfirewall2.service'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18489r369939_chk'
  tag severity: 'medium'
  tag gid: 'V-217261'
  tag rid: 'SV-217261r603262_rule'
  tag stig_id: 'SLES-12-030030'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-18487r369940_fix'
  tag satisfies: ['SRG-OS-000096-GPOS-00050', 'SRG-OS-000297-GPOS-00115', 'SRG-OS-000480-GPOS-00231', 'SRG-OS-000480-GPOS-00232']
  tag 'documentable'
  tag legacy: ['V-77435', 'SV-92131']
  tag cci: ['CCI-000382', 'CCI-002080', 'CCI-002314']
  tag nist: ['CM-7 b', 'CA-3 (5)', 'AC-17 (1)']
end
