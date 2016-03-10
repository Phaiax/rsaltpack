


#[derive(Serialize, Deserialize, Debug)]
pub struct Recipient (
    Option<String>,
    String
);

#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct Header (
    String,
    Vec<i32>,
    i32,
    String,
    String,
    Vec<Recipient>
);

#[derive(Serialize, Deserialize, Debug)]
pub struct Header2 {
    identifier: String,
    version: Vec<i32>,
    kind: i32,
    s1: String,
    s2: String,
    recipients: Vec<Recipient>
}

#[cfg(test)]
mod test {
    use super::*;
    use serde_json;

    static TEST_HEADER_JSON : &'static str = "[\"saltpack\",
      [1, 0],
      0,
      \"895e690ba0fd8d15f51adf59e161af3f67518fa6e2eaadd8a666b8a1629c2349\",
      \"b49c4c8791cd97f2c244c637df90e343eda4aaa56e37d975d2b7c81d36f44850d77706a51e2ccd57e7f7606565db4b1e\",
      [
        [
          \"wr\",
          \"c16b6126d155d7a39db20825d6c43f856689d0f8665a8da803270e0106ed91a90ef599961492bd6e49c69b43adc22724\"
        ]
      ]
    ]";
    static TEST_HEADER_SIMPLE : &'static str = "[\"saltpack\",[1,0],0,\"ad\",\"35\",[[\"wer\",\"werwt\"]]]";
    static TEST_HEADER_MOREFIELDS : &'static str = "[\"saltpack\",[1,0],0,\"ad\",\"35\",[[\"wer\",\"werwt\"]], 234]";
    static TEST_HEADER_AS_DICT : &'static str = "{\"identifier\":\"saltpack\",\"version\":[1,0],\"kind\":0,\"s1\":\"ad\",\"s2\":\"35\",\"recipients\":[[\"wer\",\"werwt\"]]}";
    static TEST_HEADER_AS_DICT_MOREFIELDS : &'static str = "{\"identifier\":\"saltpack\",\"version\":[1,0],\"kind\":0,\"s1\":\"ad\",\"s2\":\"35\",\"recipients\":[[\"wer\",\"werwt\"]], \"erg\" : 1243}";
    #[test]
    fn test() {
        assert_eq!(3, 3);
    }


    #[test]
    fn test_serde_json() {

        let point : Header = Header ("saltpack".to_string(),
                              vec![1, 0],
                              0,
                              "ad".to_string(),
                              "35".to_string(),
                              vec![ Recipient(Some("wer".to_string()), "werwt".to_string()) ]);
        let serialized = serde_json::to_string(&point).unwrap();

        println!("{}", serialized);


        let deserialized: Header = serde_json::from_str(&serialized).unwrap();
        println!("{:?}", deserialized);

        let deserialized : Result<Header, serde_json::error::Error> = serde_json::from_str(&TEST_HEADER_JSON);
        let deserialized : Result<Header, serde_json::error::Error> = serde_json::from_str(&TEST_HEADER_SIMPLE);
        println!("SIMPLE Header {:?}", deserialized);
        let deserialized : Result<Header2, serde_json::error::Error> = serde_json::from_str(&TEST_HEADER_SIMPLE);
        println!("SIMPLE Header2 {:?}", deserialized);
        let serialized = serde_json::to_string(&deserialized.unwrap()).unwrap();
        println!("{}", serialized);
        let deserialized : Header2 = serde_json::from_str(&TEST_HEADER_AS_DICT).unwrap();
        let deserialized : Result<Header2, serde_json::error::Error> = serde_json::from_str(&TEST_HEADER_AS_DICT_MOREFIELDS);
        println!("SIMPLE Header2 morefields {:?}", deserialized);

        match deserialized {
            Err(i) => { println!("{:?}", i);},
            Ok(_) => {}
        };



       // assert_eq!(3, 1);
    }
}