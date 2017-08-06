#!/bin/sh

test -f .svnignore && {
  svn propset svn:ignore --file .svnignore .
  exit 0
}
  
test -f .cvsignore && {
  svn propset svn:ignore --file .cvsignore .
  exit 0
}

echo "No .svnignore or .cvsignore file found in current directory"
exit 1

