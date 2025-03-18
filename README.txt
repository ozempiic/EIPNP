Named Pipe Impersonation PoC

This PoC demonstrates impersonation using the Named Pipe Filesystem Driver npfs and the NtFsControlFile. The goal is to test whether a server can successfully impersonate a connected client through named pipes.

Features

Creates a named pipe server (\\.\pipe\npfs).

Uses NtFsControlFile with FSCTL_PIPE_IMPERSONATE to attempt impersonation.

Passes a minimal IRP structure as an input buffer to NtFsControlFile.

Implements a client that connects with SECURITY_IMPERSONATION.

Verifies impersonation success by checking the thread token.

Installation & Compilation

Windows (MinGW / MSVC)

To compile the server:

gcc main.c -o server.exe -lntdll

Usage

Run the server first:

server.exe

Then, run the client in a separate terminal:

client.exe

Resources

Exploring Impersonation through the Named Pipe Filesystem Driver - https://mini-01-s3.vx-underground.org/samples/Papers/Windows/Internals%20and%20Analysis/2023-05-03%20-%20Exploring%20Impersonation%20through%20the%20Named%20Pipe%20Filesystem%20Driver.pdf
