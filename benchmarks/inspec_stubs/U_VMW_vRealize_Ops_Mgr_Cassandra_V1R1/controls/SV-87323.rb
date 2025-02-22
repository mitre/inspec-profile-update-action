control 'SV-87323' do
  title 'Security-relevant software updates to the Cassandra Server must be installed within the time period directed by an authoritative source (e.g., IAVM, CTOs, DTMs, and STIGs).'
  desc 'Security flaws with software applications, including database management systems, are discovered daily. Vendors are constantly updating and patching their products to address newly discovered security vulnerabilities. Organizations (including any contractor to the organization) are required to promptly install security-relevant software updates (e.g., patches, service packs, and hot fixes). Flaws discovered during security assessments, continuous monitoring, incident response activities, or information system error handling must also be addressed expeditiously. 

Organization-defined time periods for updating security-relevant software may vary based on a variety of factors including, for example, the security category of the information system or the criticality of the update (i.e., severity of the vulnerability related to the discovered flaw). 

This requirement will apply to software patch management solutions that are used to install patches across the enclave and also to applications themselves that are not part of that patch management solution. For example, many browsers today provide the capability to install their own patch software. Patch criticality, as well as system criticality, will vary. Therefore, the tactical situations regarding the patch management process will also vary. This means that the time period utilized must be a configurable parameter. Time frames for application of security-relevant software updates may be dependent upon the Information Assurance Vulnerability Management (IAVM) process.

The application will be configured to check for and install security-relevant software updates within an identified time period from the availability of the update. The specific time period will be defined by an authoritative source (e.g., IAVM, CTOs, DTMs, and STIGs).'
  desc 'check', 'Review the Cassandra Server configuration to ensure security-relevant software updates are installed within the time period directed by an authoritative source (e.g., IAVM, CTOs, DTMs, and STIGs).

Run "find / | grep "cassandra-"" from console and review all the Cassandra DB related packages currently installed on the host.

Check at the http://cassandra.apache.org/download/ for the latest updates and patches available. Check product documentation for the time period updates have to be installed on the host.

If there is an update that has to be installed, but is not displayed in the list of Cassandra DB related packages currently installed on the host, this is a finding.'
  desc 'fix', 'Configure the Cassandra Server to install security-relevant software updates within the time period directed by an authoritative source (e.g., IAVM, CTOs, DTMs, and STIGs).

Install the latest updates according to the time period specified in product documentation. Verify that the Cassandra Server was configured to follow product documentation specified updates installation timeframe.'
  impact 0.7
  ref 'DPMS Target VMware Cassandra'
  tag check_id: 'C-72847r1_chk'
  tag severity: 'high'
  tag gid: 'V-72691'
  tag rid: 'SV-87323r1_rule'
  tag stig_id: 'VROM-CS-000260'
  tag gtitle: 'SRG-APP-000456-DB-000390'
  tag fix_id: 'F-79095r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002605']
  tag nist: ['SI-2 c']
end
