#!/bin/bash

# a humorous but patriotic test script

echo "Content-Type: text/html"

echo
echo

echo "<html>"

echo "<h1>Hello World!</h1>"

echo "You are accessing us on $SERVER_PORT"

cat <<EOF
<style type="text/css">
body {background-color: black;}
li:nth-child(3n) { color: red;}
li:nth-child(3n+1) { color: white;}
li:nth-child(3n+2) { color: blue;}

@keyframes condemned_blink_effect {
  0% {
    visibility: hidden;
  }
  50% {
    visibility: hidden;
  }
  100% {
    visibility: visible;
  }
}
EOF

for ((i=0;i<100;i++));do
	
duration=`awk -v seed="$RANDOM" 'BEGIN { srand(seed);printf("%.4f\n", rand()) }'`


echo "li:nth-child($i) {  animation: ${duration}s linear infinite condemned_blink_effect; }"

done

echo "</style>"

echo "<marquee><ul>"
env | while read i; do
	echo "<li>$i</li>"
done

echo "</ul></marquee>"

echo "</html>"

