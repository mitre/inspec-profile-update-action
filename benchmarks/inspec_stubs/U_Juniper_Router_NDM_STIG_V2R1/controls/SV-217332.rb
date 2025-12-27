control 'SV-217332' do
  title 'The Juniper router must be configured to allocate audit record storage capacity in accordance with organization-defined audit record storage requirements.'
  desc 'In order to ensure network devices have a sufficient storage capacity in which to write the audit logs, they need to be able to allocate audit record storage capacity.  The task of allocating audit record storage capacity is usually performed during initial device setup if it is modifiable. 

The value for the organization-defined audit record storage requirement will depend on the amount of storage available on the network device, the anticipated volume of logs, the frequency of transfer from the network device to centralized log servers, and other factors.'
  desc 'check', 'Review the router configuration to verify that it is compliant with this requirement. The configuration example below specifies 12 archive log files and the maximum size of the active log file to be reached prior to archiving.

syslog {
       file LOG_FILE {
            any info;
            archive size 1000000 files 12;
        }
}

Note: To prevent log files from growing too large, by default the Junos logging utility writes messages to a sequence of files of a defined size. The files in the sequence are referred to as archive files to distinguish them from the active file to which messages are currently being written. The default maximum size depends on the platform type. By default, the logging utility creates up to 10 archive files in this manner. When the maximum number of archive files is reached and when the size of the active file reaches the configured maximum size, the contents of the last archived file are overwritten by the current active file. 

If the router is not configured to allocate audit record storage capacity in accordance with organization-defined audit record storage requirements, this is a finding.'
  desc 'fix', 'Configure the number or archive files and the maximum size of the active log file to be reached prior to archiving as shown in the example below.

[edit system]
set syslog file LOG_FILE any info
set syslog file LOG_FILE archive files 12 size 1000000'
  impact 0.5
  ref 'DPMS Target Juniper Router NDM'
  tag check_id: 'C-18559r296574_chk'
  tag severity: 'medium'
  tag gid: 'V-217332'
  tag rid: 'SV-217332r399877_rule'
  tag stig_id: 'JUNI-ND-000970'
  tag gtitle: 'SRG-APP-000357-NDM-000293'
  tag fix_id: 'F-18557r296575_fix'
  tag 'documentable'
  tag legacy: ['SV-101253', 'V-91153']
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']
end
