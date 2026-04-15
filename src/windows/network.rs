#[cfg(windows)]
use crate::audit::NetworkConnection;

#[cfg(windows)]
use anyhow::Result;

#[cfg(windows)]
pub fn get_process_connections(pid: u32) -> Result<Vec<NetworkConnection>> {
    use windows::Win32::NetworkManagement::IpHelper::*;
    use windows::Win32::Networking::WinSock::*;

    let mut connections = Vec::new();

    unsafe {
        // Get TCP connections
        let mut tcp_table_size = 0u32;
        let _ = GetExtendedTcpTable(
            None,
            &mut tcp_table_size,
            false,
            AF_INET.0 as u32,
            TCP_TABLE_OWNER_PID_CONNECTIONS,
            0,
        );

        if tcp_table_size > 0 {
            let mut tcp_table: Vec<u8> = vec![0; tcp_table_size as usize];
            let result = GetExtendedTcpTable(
                Some(tcp_table.as_mut_ptr() as *mut _),
                &mut tcp_table_size,
                false,
                AF_INET.0 as u32,
                TCP_TABLE_OWNER_PID_CONNECTIONS,
                0,
            );

            if result == 0 {
                // Safely interpret the table structure
                if tcp_table.len() >= 4 {
                    let num_entries = u32::from_ne_bytes([
                        tcp_table[0],
                        tcp_table[1],
                        tcp_table[2],
                        tcp_table[3],
                    ]);

                    let row_size = std::mem::size_of::<MIB_TCPROW_OWNER_PID>();
                    
                    for i in 0..num_entries {
                        let offset = 4 + (i as usize * row_size);
                        if offset + row_size <= tcp_table.len() {
                            // Safe pointer creation within bounds
                            let row_ptr = tcp_table.as_ptr().add(offset) as *const MIB_TCPROW_OWNER_PID;
                            let row = &*row_ptr;

                            if row.dwOwningPid == pid {
                                let local_addr = format!(
                                    "{}.{}.{}.{}",
                                    (row.dwLocalAddr & 0xFF) as u8,
                                    ((row.dwLocalAddr >> 8) & 0xFF) as u8,
                                    ((row.dwLocalAddr >> 16) & 0xFF) as u8,
                                    ((row.dwLocalAddr >> 24) & 0xFF) as u8,
                                );

                                let remote_addr = format!(
                                    "{}.{}.{}.{}",
                                    (row.dwRemoteAddr & 0xFF) as u8,
                                    ((row.dwRemoteAddr >> 8) & 0xFF) as u8,
                                    ((row.dwRemoteAddr >> 16) & 0xFF) as u8,
                                    ((row.dwRemoteAddr >> 24) & 0xFF) as u8,
                                );

                                let local_port = ((row.dwLocalPort >> 8) & 0xFF
                                    | ((row.dwLocalPort & 0xFF) << 8))
                                    as u16;
                                let remote_port = ((row.dwRemotePort >> 8) & 0xFF
                                    | ((row.dwRemotePort & 0xFF) << 8))
                                    as u16;

                                connections.push(NetworkConnection {
                                    local_address: local_addr,
                                    local_port,
                                    remote_address: remote_addr,
                                    remote_port,
                                    protocol: "TCP".to_string(),
                                    state: format_tcp_state(row.dwState),
                                    data_sent: None,
                                    data_received: None,
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(connections)
}

#[cfg(windows)]
#[allow(dead_code)]
fn format_tcp_state(state: u32) -> String {
    // TCP state constants are i32, so we cast and compare
    use windows::Win32::NetworkManagement::IpHelper::*;

    let state_i32 = state as i32;

    if state_i32 == MIB_TCP_STATE_CLOSED.0 {
        "CLOSED"
    } else if state_i32 == MIB_TCP_STATE_LISTEN.0 {
        "LISTEN"
    } else if state_i32 == MIB_TCP_STATE_SYN_SENT.0 {
        "SYN_SENT"
    } else if state_i32 == MIB_TCP_STATE_SYN_RCVD.0 {
        "SYN_RCVD"
    } else if state_i32 == MIB_TCP_STATE_ESTAB.0 {
        "ESTABLISHED"
    } else if state_i32 == MIB_TCP_STATE_FIN_WAIT1.0 {
        "FIN_WAIT1"
    } else if state_i32 == MIB_TCP_STATE_FIN_WAIT2.0 {
        "FIN_WAIT2"
    } else if state_i32 == MIB_TCP_STATE_CLOSE_WAIT.0 {
        "CLOSE_WAIT"
    } else if state_i32 == MIB_TCP_STATE_CLOSING.0 {
        "CLOSING"
    } else if state_i32 == MIB_TCP_STATE_LAST_ACK.0 {
        "LAST_ACK"
    } else if state_i32 == MIB_TCP_STATE_TIME_WAIT.0 {
        "TIME_WAIT"
    } else {
        "UNKNOWN"
    }
    .to_string()
}
