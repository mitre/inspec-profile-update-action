control 'SV-87765' do
  title 'The virtual tunnel endpoint (VTEP) must be dual-homed to two physical network nodes.'
  desc 'If uplink connectivity for the VTEP to the Virtual Extensible Local Area Network (VXLAN) transport network fails, traffic to and from the VM servers resident on the affected hypervisor host is dropped. Whether it is a hardware (VXLAN-enabled switch) or software (hypervisor resident) VTEP, dedicating a pair of physical uplinks from the VTEP to two separate network nodes adds high availability and resiliency to the VXLAN implementation. If either an uplink or one of the attached network nodes fails, the VTEP would still have connectivity to the underlying IP network for VXLAN traffic.'
  desc 'check', 'Review the VXLAN topology and the configuration of all hypervisor hosts and VXLAN-enabled switches to verify that every VTEP is dual-homed to two physical network nodes. 

If any VTEPs are not dual-homed to two physical network nodes, this is a finding.

Note: This requirement is only applicable to VNIs that must be defined on each VXLAN-enabled switch. In addition, this requirement is applicable to the implementation of technologies similar to VXLAN (e.g., NVGRE, STT) for the purpose of transporting traffic between virtual machines residing on different physical hosts.'
  desc 'fix', 'Configure all hypervisor hosts and VXLAN-enabled switches so the VTEP will be dual-homed to two physical network nodes. 

In the case of the VXLAN-enabled switch, the VTEP will be the loopback interface; hence, dual-homing can be achieved by having two links going upstream to two switches or to two routers. 

The hypervisor can use network interface card (NIC) teaming for the VTEP interface, with each link connected to an access switch.'
  impact 0.3
  ref 'DPMS Target Software Defined Networking (SDN) Policy'
  tag check_id: 'C-73247r1_chk'
  tag severity: 'low'
  tag gid: 'V-73113'
  tag rid: 'SV-87765r1_rule'
  tag stig_id: 'NET-SDN-024'
  tag gtitle: 'NET-SDN-024'
  tag fix_id: 'F-79559r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
