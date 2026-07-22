"""
Example 4: Style and maintainability issues.
Expected findings: missing type hints, missing docstrings, overly long
function, naming convention violations, magic numbers.
Good demo case for the style pass and pylint comparison, since pylint
catches most of these same issues (useful diff to show in the UI).
"""
import os,sys

def proc(d,f,x,y,z,w,v,u,t,s,r,q,p):
    A=d+f
    B=x*y
    C=z-w
    D=v+u
    E=t*s
    F=r-q
    G=p
    if A>100:
        if B>50:
            if C>25:
                if D>10:
                    return A+B+C+D+E+F+G
                else:
                    return A+B+C+D
            else:
                return A+B
        else:
            return A
    return 0

class myClass:
    def __init__(self,n,a,e):
        self.n=n
        self.a=a
        self.e=e

    def getData(self):
        return self.n,self.a,self.e

    def setData(self,n,a,e):
        self.n=n
        self.a=a
        self.e=e

TIMEOUT=30
MAX=1000
MIN=0

def calculate(val):
    return val*2+10-5*3
