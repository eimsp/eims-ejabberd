#!/bin/sh
# This script is used to prepare the development environment for ejabberd.
# To make hard-link to eims-ejabberd/www in dir ejabberd/eims/.
# To copy from eims-ejabberd/etc:
#   - script start-dev.sh to ejabberd dir (ejabberd),
#   - sys.config  to ejabberd/rel/ejabberd.yml,




echo -n "===> Preparing dev configuration files: "
# Start from eims-ejabberd dir
EIMS_DIR=`pwd`

cd ../ejabberd

rm -rf ./src/mod_muc_room.erl
rm -rf ./src/mod_mam_sql.erl
rm -rf ./src/mod_mam.erl
rm -rf ./src/ejabberd_oauth.erl


if [ ! -d "./src/eims" ]; then
    echo -n "src/eims " \
    && ln -s $EIMS_DIR/src ./src/eims
fi

if [ ! -f "start-dev.sh" ] ; then
    echo -n "start-dev.sh " \
    && cp $EIMS_DIR/etc/start-dev.sh start-dev.sh
fi

if [ ! -d "eims" ]; then
    echo -n "eims" \
    && mkdir eims      \
    && ln -s $EIMS_DIR/www ./eims/www
fi

if [ ! -d "./etc" ]; then
    echo -n "etc" \
    && mkdir etc # It needs for dev version to copy dictionaries to this dir
    #&& mkdir etc/ejabberd
    #&& cp -f $EIMS_DIR/etc/ejabberd.yml ./etc/ejabberd/ejabberd.yml
fi



cp -rf $EIMS_DIR/include ./
cp -f $EIMS_DIR/etc/blacklist_en.txt ./etc/blacklist_en.txt
cp -f $EIMS_DIR/etc/charmap ./etc/charmap_en.txt
cp -f $EIMS_DIR/etc/sys.config ./rel/sys.config
cp -rf $EIMS_DIR/priv ./
cp -f $EIMS_DIR/src/ejabberd.app.src.script ./src/ejabberd.app.src.script

cd ..

if [ ! -d "./pv/upload" ]; then
    echo -n "pv/upload" \
    && mkdir -p pv/upload # It needs for upload dir
fi

if [ ! -d "./database" ]; then
    echo -n "database" \
    && mkdir database # It needs for DataBase dir
fi


#PWD_DIR=`pwd`
#REL_DIR=$PWD_DIR/_build/dev/rel/ejabberd
#CON_DIR=$REL_DIR/etc/ejabberd
#
#
#[ -z "$REL_DIR_TEMP" ] && REL_DIR_TEMP=$REL_DIR && echo $REL_DIR_TEMP
#CON_DIR_TEMP=$REL_DIR_TEMP/etc/ejabberd/
#BIN_DIR_TEMP=$REL_DIR_TEMP/bin/

#if [ -r $CON_DIR ]; then
#  cd $CON_DIR_TEMP \

#sed -i "s|# certfiles:|certfiles:\n  - $CON_DIR/cert.pem|g" ejabberd.yml.example
#sed -i "s|certfiles:|ca_file: $CON_DIR/ca.pem\ncertfiles:|g" ejabberd.yml.example
#sed -i 's|^acl:$|acl:\n  admin: [user: admin]|g' ejabberd.yml.example
#  if [ ! -f "$CON_DIR/ejabberd.yml.development" ]; then
#    echo -n "Update ejabberd.yml " \
#    && cp -rf $EIMS_DIR/etc/ejabberd.yml.development ejabberd.yml.development
#  fi
#sed -i "s|#' POLL|EJABBERD_BYPASS_WARNINGS=true\n\n#' POLL|g" ejabberdctl.cfg.example
#  cp  $EIMS_DIR/etc/ejabberd.yml ejabberd.yml
#fi

echo ""
echo "===> Some example ways to start this ejabberd dev:"
echo "     _build/dev/rel/ejabberd/bin/ejabberd console"
echo "     _build/dev/rel/ejabberd/bin/ejabberdctl live"
