%{
//header section insert into output
#include "paren.h"
#include "parser.h"
#include <stdio.h>
%}

%option outfile="lexer.c" header-file="lexer.h"
%option warn nodefault

%option reentrant noyywrap never-interactive nounistd
%option bison-bridge

LPAREN "("
RPAREN ")"
LBRACK "["
RBRACK "]"
LCBRACK "{"
RCBRACK "}"
LABRACK "<"
RABRACK ">"

WS	[ \t\r\n]+

/* begin tokenizing*/
%%
{WS} { /*ignore white spaces, we are kind*/ }
{LPAREN} {return TOKEN_LPAREN;}
{RPAREN} {return TOKEN_RPAREN;}
{LBRACK} {return TOKEN_LBRACK;}
{RBRACK} {return TOKEN_RBRACK;}
{LCBRACK} {return TOKEN_LCBRACK;}
{RCBRACK} {return TOKEN_RCBRACK;}
{LABRACK} {return TOKEN_LABRACK;}
{RABRACK} {return TOKEN_RABRACK;}

. { /*error */ } 

%%

