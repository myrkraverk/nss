
// Copyright 2017 Johann 'Myrkraverk' Oskarsson <johann@myrkraverk.com>
// License: WTFPL 2; see bottom of the file.

// 29.03.2017
// ----------
// This example is incorrect, and it's only to be used in conjunction
// with the blog at https://wp.me/p4w9PF-4U

// 28.03.2017
// ----------
// To run this, you need to create a certificate database and (maybe)
// install an example (self signed) certificate in it.  I have not
// tested this with an empty database.

// For example,

// $ mkdir /tmp/dblfreedb

// $ echo foo > /tmp/dblfreedb/passwd

// $ certutil -N -d sql:/tmp/dblfreedb -f /tmp/dblfreedb/passwd

// $ certutil -S -f /tmp/dblfreedb/passwd -d sql:/tmp/dblfreedb \
//     -t "C,," -x -n "foo" -g 2048 -s "CN=foo,O=foo,L=bar,ST=baz,C=EL"

// That last command will need to be copied and pasted in steps, to
// get rid of the C comment syntax.

// NSPR include files
#include <prnetdb.h>
#include <prprf.h>
#include <prmem.h>

// NSS include files
#include <nss.h>
#include <pk11pub.h>
#include <ssl.h>

// The simplest password function ever, fail on retry, or return the argument. 
char *passwd_function( PK11SlotInfo __unused *info, PRBool retry, void *arg ) {
  if ( retry == PR_TRUE ) return 0;
  return arg;
}

int main( int __unused argc, char * __unused argv[] )
{
  SECStatus sec_status = SECFailure;
  PRFileDesc *output = PR_GetSpecialFD( PR_StandardOutput );

  // Programmer's error checking; the error code in the shell shows the line
  // number that failed.  This is adequate for a simple demonstration.
  sec_status = NSS_Init( "sql:/tmp/dblfreedb" );
  if ( sec_status != SECSuccess ) return __LINE__;

  PK11_SetPasswordFunc( passwd_function );

  // Originally, the password was read from a file, but in this example, 
  // it's hard coded and copied into the allocated buffer.
  char hard_coded_password[] = "foo";

  char *passwd = PR_Malloc( sizeof hard_coded_password );

  // This is a zero terminating version of strncpy(); essentially the same
  // as BSD's strlcpy().
  PL_strncpyz( passwd, hard_coded_password, sizeof hard_coded_password );

  // Print out the password, so our program apears to do at least something. 
  // Not at all relevant to the problem at hand.
  PR_fprintf( output, "Password is: %s\n", passwd );

  // We need some minimal TCP setup code, to get the double free to manifest. 
  PRFileDesc *listen_fd = PR_NewTCPSocket();
  if ( ! listen_fd ) return __LINE__;

  listen_fd = SSL_ImportFD( /* no model */ 0, listen_fd );
  if ( ! listen_fd ) return __LINE__;

  // Now we can set the password argument; this is required for the double
  // free to manifest.
  { int i = SSL_SetPKCS11PinArg( listen_fd, passwd );
    if ( i ) return __LINE__;
  }

  CERTCertificate *certificate = PK11_FindCertFromNickname( "foo", passwd );
  if ( ! certificate ) return __LINE__;

  SECKEYPrivateKey *key = PK11_FindKeyByAnyCert( certificate, passwd );
  if ( ! key ) return __LINE__;


  // At this point, this is a double free; even though nothing in our code
  // indicates it should be.
  PR_Free( passwd );

  return 0;
}

//           DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
//                     Version 2, December 2004

// Copyright (C) 2004 Sam Hocevar <sam@hocevar.net> 

// Everyone is permitted to copy and distribute verbatim or modified 
// copies of this license document, and changing it is allowed as long 
// as the name is changed. 

//           DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
//   TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION

//  0. You just DO WHAT THE FUCK YOU WANT TO.

