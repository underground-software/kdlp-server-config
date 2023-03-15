#!/bin/bash

#htpasswd -vb .htpasswd admin redhat

KDLP_ROOT=/var/www/html/kdlp.underground.software
MARKDOWN_TARGET=${KDLP_ROOT}/${PATH_INFO}


exit_fail(){
	echo -e "Content-Type: text/html\n\n"

	cat ${KDLP_ROOT}/nav ${KDLP_ROOT}/header
	echo "<h1>HTTP ERROR ${1}</h1>"
	exit 0
}


AUTH_USERPASS=`echo "${HTTP_AUTHORIZATION}" | base64 -d`
AUTH_USER=` echo "${AUTH_USERPASS}" | awk 'BEGIN {FS=":"} {print $1}' `
AUTH_PASS=` echo "${AUTH_USERPASS}" | awk 'BEGIN {FS=":"} {print $2}' `

KDLP_SQLITE="sqlite3 /var/www/db/kdlp-test.db"

# check for students, lookup
STUDENT_ID=0
STUDENT_NAME=" "
if echo "${PATH_INFO}" | grep -E "/auth/students/[[:digit:]]+" >/dev/null; then
	MARKDOWN_TARGET="${KDLP_ROOT}/auth/students/_INT_/index.md"
	STUDENT_ID=`basename ${PATH_INFO} | sed -e 's/...$//'`
	STUDENT_NAME=`${KDLP_SQLITE} "select name from students where id is ${STUDENT_ID}"`
	STUDENT_GRADE=`${KDLP_SQLITE} "select grade from students where id is ${STUDENT_ID}"`
fi

if [ ! -f ${MARKDOWN_TARGET} ]; then
	MARKDOWN_TARGET=${KDLP_ROOT}/404.md
fi
if [ -z ${HTTP_AUTHORIZATION} ]; then
	echo "Status: 401 Unauthorized"
	echo "WWW-Authenticate: basic"
	exit_fail "401: UNAUTHORIZED"
else
	if [ `echo -n "admin:redhat" | base64` != "${HTTP_AUTHORIZATION}" ]; then
		echo "Status: 403 Forbidden"
		exit_fail "403: FORBIDDEN"
	fi
fi
echo -e "Content-Type: text/html\n\n"

STUDENT_COUNT=` ${KDLP_SQLITE} 'select COUNT (id) from students;'`


STUDENT_LIST_FILE=`mktemp`
echo -e "|ID|Name\n|--|--|" > ${STUDENT_LIST_FILE}
for ((i=1;${i}<=${STUDENT_COUNT}; ++i)); do
	STUDENT_NAME_ITER=`${KDLP_SQLITE} "select name from students where id is $i"`
	echo -e "|${i}|[${STUDENT_NAME_ITER}](/auth/students/$i)|" >> ${STUDENT_LIST_FILE}
done

# to temp make a databse http context rw in selinux:
#chcon -t httpd_sys_rw_content_t /var/lib/myapp/database.sqlite
	
if [ "${STUDENT_ID}" -gt "1" ]; then
	PREV=`echo "${STUDENT_ID} - 1" | bc`
	PREV_GEN="\[<--PREV\]\(\/auth\/students\/${PREV}\)"
else
	PREV=0
	PREV_GEN="<--START"
fi


if [ "${STUDENT_ID:-0}" -lt ${STUDENT_COUNT} ]; then
	NEXT=`echo "${STUDENT_ID} + 1" | bc`
	NEXT_GEN="\[NEXT-->\]\(\/auth\/students\/${NEXT}\)"
else
	NEXT=0
	NEXT_GEN="END-->"
fi

UP_GEN='\[|^UP^|\]\(\/auth\/students\/index.md\)'

markdown_() {
	markdown <(sed -e "
		s/@AUTH_USER@/${AUTH_USER}/g
		s/@AUTH_PASS@/${AUTH_PASS}/g
		s/@STUDENT_NAME@/${STUDENT_NAME}/g
		s/@STUDENT_GRADE@/${STUDENT_GRADE}/g
		s/@STUDENT_ID@/${STUDENT_ID}/g
		s/@PREV@/${PREV_GEN}/g
		s/@NEXT@/${NEXT_GEN}/g
		s/@UP@/${UP_GEN}/g
		/@STUDENT_LIST@/ { r ${STUDENT_LIST_FILE}
			d
		}
			
	" ${1})
}

cat \
	${KDLP_ROOT}/nav \
	${KDLP_ROOT}/nav_auth \
	${KDLP_ROOT}/header \
	<(markdown_ ${MARKDOWN_TARGET})
