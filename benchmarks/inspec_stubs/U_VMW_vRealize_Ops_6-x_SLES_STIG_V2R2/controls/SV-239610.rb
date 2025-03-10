control 'SV-239610' do
  title 'The SLES for vRealize must implement cryptographic mechanisms to protect the confidentiality of nonlocal maintenance and diagnostic communications, when used for nonlocal maintenance sessions.'
  desc 'Privileged access contains control and configuration information and is particularly sensitive, so additional protections are necessary. This is maintained by using cryptographic mechanisms such as encryption to protect confidentiality.

Nonlocal maintenance and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network (e.g., the Internet) or an internal network. Local maintenance and diagnostic activities are those activities carried out by individuals physically present at the information system or information system component and not communicating across a network connection. 

This requirement applies to hardware/software diagnostic test equipment or tools. This requirement does not cover hardware/software components that may support information system maintenance, yet are a part of the system (e.g., the software implementing "ping," "ls," "ipconfig," or the hardware and software implementing the monitoring port of an Ethernet switch).

The SLES for vRealize can meet this requirement through leveraging a cryptographic module.'
  desc 'check', %q(Check the SSH daemon configuration for allowed MACs:

# grep -i macs /etc/ssh/sshd_config | grep -v '^#' 

If no lines are returned, or the returned MACs list contains any MAC other than "hmac-sha1", this is a finding.)
  desc 'fix', 'Edit the SSH daemon configuration and remove any MACs other than "hmac-sha1". If necessary, add a "MACs" line.

# sed -i "/^[^#]*MACs/ c\\MACs hmac-sha1" /etc/ssh/sshd_config'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x SLES'
  tag check_id: 'C-42843r662279_chk'
  tag severity: 'medium'
  tag gid: 'V-239610'
  tag rid: 'SV-239610r877381_rule'
  tag stig_id: 'VROM-SL-001230'
  tag gtitle: 'SRG-OS-000394-GPOS-00174'
  tag fix_id: 'F-42802r662280_fix'
  tag 'documentable'
  tag legacy: ['SV-99341', 'V-88691']
  tag cci: ['CCI-003123']
  tag nist: ['MA-4 (6)']
end
