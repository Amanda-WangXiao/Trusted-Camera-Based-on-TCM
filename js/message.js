/**
 * Created by algorist on 2016/3/26.
 */


//var type_list={MESSAGE:{},LOGIN:{}};
//type_list["MESG"]={LOGIN_INFO:{},RETURN:{}};

function Cube_msg(type,subtype) {
    this.data={HEAD:{tag:"MESG",version:65537,record_type:type,record_subtype:subtype,
        flow:0,record_num:0,expand_num:0,nonce:''},RECORD:[],EXPAND:[]};
}
Cube_msg.prototype = {
    addrecord: function(x) {
        this.data.RECORD[this.data.HEAD.record_num]=x;
        this.data.HEAD.record_num++;
        return this.data.HEAD.record_num;
    },
    addexpand: function(x) {
        this.data.EXPAND[this.data.HEAD.expand_num] = x;
        this.data.HEAD.expand_num++;
        return this.data.HEAD.expand_num;
    },
    output: function()  {
        return JSON.stringify(this.data);
    }
};