#!/system/bin/sh
if [ "$#" -ne 2 ]; then
  echo "Error: Usage : cowpy.sh [src] [dst]" >&2
  exit 1
elif ! [ -r "$1" ] || ! [ -r "$2" ]; then
  echo "Error: Files are not readable/not exist" >&2
  exit 1
fi

compsha1() {
  [ "$(sha1sum "$1" | cut -d' ' -f1)" != "$(sha1sum "$2" | cut -d' ' -f1)" ]
  return $?
}

docowpy() {
  ./cowpy $1 $2
  a=1
  while [ "$a" -le 10 ]; do
    if compsha1 $1 $2; then
      echo "Trying again $a"
      ./cowpy $1 $2
    else
      break
    fi
    a=$((a+1))
  done
  compsha1 $1 $2 && echo -e "\nFailed to cowpy."
}

dstlen="$(busybox ls -l "$2" | awk '{print $5}')"
srclen="$(busybox ls -l "$1" | awk '{print $5}')"
extlen="$((dstlen-srclen))"

if [ "$srclen" -lt "$dstlen" ]; then
  dd if=/dev/zero of=temp bs=1 count=$extlen 2>/dev/null
  cp $1 ${1}.temp
  cat temp >> ${1}.temp
  rm -f temp
  docowpy ${1}.temp $2
  rm -f ${1}.temp
elif [ "$srclen" -gt "$dstlen" ]; then
  ./cowpy $1 $2
else
  docowpy $1 $2
fi
