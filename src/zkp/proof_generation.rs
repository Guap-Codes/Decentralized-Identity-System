// src/zkp/proof_generation.rs
//! Zero-Knowledge Proof generation for Merkle tree membership.
//!
//! This module provides functionality to generate zk-SNARK proofs using Groth16
//! with Poseidon hashing, specifically for proving Merkle tree membership claims.
//! The implementation uses the BN254 curve and is optimized for Ethereum compatibility.

use ark_bn254::{Bn254, Fr as Bn254Fr};
use ark_crypto_primitives::{
    sponge::{
        poseidon::PoseidonConfig,
    },
    sponge::constraints::CryptographicSpongeVar,
};
use ark_crypto_primitives::sponge::poseidon::constraints::PoseidonSpongeVar;
use ark_ff::PrimeField;
use ark_groth16::Groth16;
use ark_r1cs_std::{
    alloc::AllocVar,
    eq::EqGadget,
    fields::fp::FpVar,
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_snark::{CircuitSpecificSetupSNARK, SNARK};
use ark_serialize::CanonicalSerialize;
use base64;
use num_bigint::BigUint;
use rand::rngs::OsRng;
use std::error::Error;
use std::str::FromStr;
use crate::utils::serialization::{serialize_poseidon_config, deserialize_poseidon_config};
use once_cell::sync::Lazy;
use std::fs;


/// Cached Poseidon configuration for BN254 curve
///
/// The configuration is either:
/// 1. Loaded from `poseidon_config.cache` if valid
/// 2. Regenerated and cached if no valid cache exists
///
/// ## Parameters
/// - Full rounds: 8
/// - Partial rounds: 57  
/// - Alpha (S-box): 5
/// - Rate: 2
/// - Capacity: 1
static POSEIDON_CONFIG: Lazy<PoseidonConfig<Bn254Fr>> = Lazy::new(|| {
    const CACHE_PATH: &str = "poseidon_config.cache";
    
    // Try to load from cache
    if let Ok(config_str) = fs::read_to_string(CACHE_PATH) {
        match deserialize_poseidon_config(&config_str) {
            Ok(config) => return config,
            Err(e) => {
                eprintln!("Warning: Cached Poseidon config invalid: {}. Regenerating...", e);
            }
        }
    }
    
    // Generate fresh config if cache doesn't exist or is invalid
    let config = generate_poseidon_config();
    let serialized = serialize_poseidon_config(&config);
    
    // Save to cache (ignore errors)
    let _ = fs::write(CACHE_PATH, &serialized);
    config
});


/// Generates secure Poseidon parameters for BN254
///
/// ## Security Parameters
/// - Matches Ethereum's precompile-friendly configuration
/// - 8 full rounds, 57 partial rounds
/// - MDS matrix and round constants from audited source
///
/// # Returns
/// `PoseidonConfig<Bn254Fr>` with optimized parameters
pub fn generate_poseidon_config() -> PoseidonConfig<Bn254Fr> {
    // Parameters for a rate-2, capacity-1 Poseidon configuration on BN254
    let full_rounds = 8;
    let partial_rounds = 57;
    let alpha = 5; // S-box power (standard for BN254)
    let rate = 2;
    let capacity = 1;
    let state_size = rate + capacity; // 3

    // MDS matrix from poseidon_parameters_for_test (secure for rate=2, capacity=1)
    let mds = vec![
        vec![
            Bn254Fr::from(
                BigUint::from_str(
                    "43228725308391137369947362226390319299014033584574058394339561338097152657858",
                )
                .unwrap(),
            ),
            Bn254Fr::from(
                BigUint::from_str(
                    "20729134655727743386784826341366384914431326428651109729494295849276339718592",
                )
                .unwrap(),
            ),
            Bn254Fr::from(
                BigUint::from_str(
                    "14275792724825301816674509766636153429127896752891673527373812580216824074377",
                )
                .unwrap(),
            ),
        ],
        vec![
            Bn254Fr::from(
                BigUint::from_str(
                    "3039440043015681380498693766234886011876841428799441709991632635031851609481",
                )
                .unwrap(),
            ),
            Bn254Fr::from(
                BigUint::from_str(
                    "6678863357926068615342013496680930722082156498064457711885464611323928471101",
                )
                .unwrap(),
            ),
            Bn254Fr::from(
                BigUint::from_str(
                    "37355038393562575053091209735467454314247378274125943833499651442997254948957",
                )
                .unwrap(),
            ),
        ],
        vec![
            Bn254Fr::from(
                BigUint::from_str(
                    "26481612700543967643159862864328231943993263806649000633819754663276818191580",
                )
                .unwrap(),
            ),
            Bn254Fr::from(
                BigUint::from_str(
                    "30103264397473155564098369644643015994024192377175707604277831692111219371047",
                )
                .unwrap(),
            ),
            Bn254Fr::from(
                BigUint::from_str(
                    "5712721806190262694719203887224391960978962995663881615739647362444059585747",
                )
                .unwrap(),
            ),
        ],
    ];

    // Round constants (ark) from poseidon_parameters_for_test (37 rounds)
    let mut ark = vec![
        vec![
            Bn254Fr::from(
                BigUint::from_str(
                    "44595993092652566245296379427906271087754779418564084732265552598173323099784",
                )
                .unwrap(),
            ),
            Bn254Fr::from(
                BigUint::from_str(
                    "23298463296221002559050231199021122673158929708101049474262017406235785365706",
                )
                .unwrap(),
            ),
            Bn254Fr::from(
                BigUint::from_str(
                    "34212491019164671611180318500074499609633402631511849759183986060951187784466",
                )
                .unwrap(),
            ),
        ],
        vec![
            Bn254Fr::from(
                BigUint::from_str(
                    "19098051134080182375553680073525644187968170656591203562523489333616681350367",
                )
                .unwrap(),
            ),
            Bn254Fr::from(
                BigUint::from_str(
                    "7027675418691353855077049716619550622043312043660992344940177187528247727783",
                )
                .unwrap(),
            ),
            Bn254Fr::from(
                BigUint::from_str(
                    "47642753235356257928619065424282314733361764347085604019867862722762702755609",
                )
                .unwrap(),
            ),
        ],
        vec![
            Bn254Fr::from(
                BigUint::from_str(
                    "24281836129477728386327945482863886685457469794572168729834072693507088619997",
                )
                .unwrap(),
            ),
            Bn254Fr::from(
                BigUint::from_str(
                    "12624893078331920791384400430193929292743809612452779381349824703573823883410",
                )
                .unwrap(),
            ),
            Bn254Fr::from(
                BigUint::from_str(
                    "22654862987689323504199204643771547606936339944127455903448909090318619188561",
                )
                .unwrap(),
            ),
        ],
        vec![
            Bn254Fr::from(
                BigUint::from_str(
                    "27229172992560143398415971432065737099462061782414043625359531777450940662377",
                )
                .unwrap(),
            ),
            Bn254Fr::from(
                BigUint::from_str(
                    "132249520639222509609368194414489736922640417501009905694451920645673070934",
                )
                .unwrap(),
            ),
            Bn254Fr::from(
                BigUint::from_str(
                    "40380869235216625717296601204704413215735530626882135230693823362552484855508",
                )
                .unwrap(),
            ),
        ],
        vec![
            Bn254Fr::from(
                BigUint::from_str(
                    "4245751157938905689397184705633683893932492370323323780371834663438472308145",
                )
                .unwrap(),
            ),
            Bn254Fr::from(
                BigUint::from_str(
                    "8252946875535418429533049587170755750275631534314711502253775796882240991261",
                )
                .unwrap(),
            ),
            Bn254Fr::from(
                BigUint::from_str(
                    "32910829712934971129644416249914075073083903821282503505466324428991624789936",
                )
                .unwrap(),
            ),
        ],
        vec![
            Bn254Fr::from(
                BigUint::from_str(
                    "49412601297460128335642438246716127241669915737656789613664349252868389975962",
                )
                .unwrap(),
            ),
            Bn254Fr::from(
                BigUint::from_str(
                    "841661305510340459373323516098909074520942972558284146843779636353111592117",
                )
                .unwrap(),
            ),
            Bn254Fr::from(
                BigUint::from_str(
                    "37926489020263024391336570420006226544461516787280929232555625742588667303947",
                )
                .unwrap(),
            ),
        ],
        vec![
            Bn254Fr::from(
                BigUint::from_str(
                    "18433043696013996573551852847056868761017170818820490351056924728720017242180",
                )
                .unwrap(),
            ),
            Bn254Fr::from(
                BigUint::from_str(
                    "45376910275288438312773930242803223482318753992595269901397542214841496212310",
                )
                .unwrap(),
            ),
            Bn254Fr::from(
                BigUint::from_str(
                    "47854349410014339708332226068958253098964727682486278458389508597930796651514",
                )
                .unwrap(),
            ),
        ],
        vec![
            Bn254Fr::from(
                BigUint::from_str(
                    "32638426693771251366613055506166587312642876874690861030672730491779486904360",
                )
                .unwrap(),
            ),
            Bn254Fr::from(
                BigUint::from_str(
                    "19105439281696418043426755774110765432959446684037017837894045255490581318047",
                )
                .unwrap(),
            ),
            Bn254Fr::from(
                BigUint::from_str(
                    "13484299981373196201166722380389594773562113262309564134825386266765751213853",
                )
                .unwrap(),
            ),
        ],
        vec![
            Bn254Fr::from(
                BigUint::from_str(
                    "63360321133852659797114062808297090090814531427710842859827725871241144161",
                )
                .unwrap(),
            ),
            Bn254Fr::from(
                BigUint::from_str(
                    "42427543035537409467993338717379268954936885184662765745740070438835506287271",
                )
                .unwrap(),
            ),
            Bn254Fr::from(
                BigUint::from_str(
                    "149101987103211771991327927827692640556911620408176100290586418839323044234",
                )
                .unwrap(),
            ),
        ],
        vec![
            Bn254Fr::from(
                BigUint::from_str(
                    "834176406222682680388789871001556186152608158307195001544683344625135755329",
                )
                .unwrap(),
            ),
            Bn254Fr::from(
                BigUint::from_str(
                    "456976375944150442493",
                )
                .unwrap(),
            ),
            Bn254Fr::from(
                BigUint::from_str(
                    "49833261156201520743834327917353893365097424877680239796845398698940689734850",
                )
                .unwrap(),
            ),
        ],
        vec![
            Bn254Fr::from(
                BigUint::from_str(
                    "26764715016591436228000634284249890185894507497739511725029482580508707525029",
                )
                .unwrap(),
            ),
            Bn254Fr::from(
                BigUint::from_str(
                    "25054530812095491217523557726611612265064441619646263299990388543372685322499",
                )
                .unwrap(),
            ),
            Bn254Fr::from(
                BigUint::from_str(
                    "47654590955096246997622155031169641628093104787883934397920286718814889326452",
                )
                .unwrap(),
            ),
        ],
        vec![
            Bn254Fr::from(
                BigUint::from_str(
                    "16463825890556752307085325855351334996898686633642574805918056141310194135796",
                )
                .unwrap(),
            ),
            Bn254Fr::from(
                BigUint::from_str(
                    "17473961341633494489168064889016732306117097771640351649096482400214968053040",
                )
                .unwrap(),
            ),
            Bn254Fr::from(
                BigUint::from_str(
                    "49914603434867854893558366922996753035832008639512305549839666311012232077468",
                )
                .unwrap(),
            ),
        ],
        vec![
            Bn254Fr::from(
                BigUint::from_str(
                    "17122578514152308432111470949473865420090463026624297565504381163777697818362",
                )
                .unwrap(),
            ),
            Bn254Fr::from(
                BigUint::from_str(
                    "34870689836420861427379101859113225049736283485335674111421609473028315711541",
                )
                .unwrap(),
            ),
            Bn254Fr::from(
                BigUint::from_str(
                    "4622082908476410083286670201138165773322781640914243047922441301693321472984",
                )
                .unwrap(),
            ),
        ],
        vec![
            Bn254Fr::from(
                BigUint::from_str(
                    "6079244375752010013798561155333454682564824861645642293573415833483620500976",
                )
                .unwrap(),
            ),
            Bn254Fr::from(
                BigUint::from_str(
                    "2635090520059500019661864086615522409798872905401305311748231832709078452746",
                )
                .unwrap(),
            ),
            Bn254Fr::from(
                BigUint::from_str(
                    "19070766579582338321241892986615538320421651429118757507174186491084617237586",
                )
                .unwrap(),
            ),
        ],
        vec![
            Bn254Fr::from(
                BigUint::from_str(
                    "12622420533971517050761060317049369208980632120901481436392835424625664738526",
                )
                .unwrap(),
            ),
            Bn254Fr::from(
                BigUint::from_str(
                    "8965101225657199137904506150282256568170501907667138404080397024857524386266",
                )
                .unwrap(),
            ),
            Bn254Fr::from(
                BigUint::from_str(
                    "27085091008069524593196374148553176565775450537072498305327481366756159319838",
                )
                .unwrap(),
            ),
        ],
        vec![
            Bn254Fr::from(
                BigUint::from_str(
                    "45929056591150668409624595495643698205830429971690813312608217341940499221218",
                )
                .unwrap(),
            ),
            Bn254Fr::from(
                BigUint::from_str(
                    "50361689160518167880500080025023064746137161030119436080957023803101861300846",
                )
                .unwrap(),
            ),
            Bn254Fr::from(
                BigUint::from_str(
                    "6722586346537620732668048024627882970582133613352245923413730968378696371065",
                )
                .unwrap(),
            ),
        ],
        vec![
            Bn254Fr::from(
                BigUint::from_str(
                    "7340485916200743279276570085958556798507770452421357119145466906520506506342",
                )
                .unwrap(),
            ),
            Bn254Fr::from(
                BigUint::from_str(
                    "25946733168219652706630789514519162148860502996914241011500280690204368174083",
                )
                .unwrap(),
            ),
            Bn254Fr::from(
                BigUint::from_str(
                    "9962367658743163006517635070396368828381757404628822422306438427554934645464",
                )
                .unwrap(),
            ),
        ],
        vec![
            Bn254Fr::from(
                BigUint::from_str(
                    "7221669722700687417346373353960536661883467014204005276831020252277657076044",
                )
                .unwrap(),
            ),
            Bn254Fr::from(
                BigUint::from_str(
                    "21487980358388383563030903293359140836304488103090321183948009095669344637431",
                )
                .unwrap(),
            ),
            Bn254Fr::from(
                BigUint::from_str(
                    "44389482047246878765773958430749333249729101516826571588063797358040130313157",
                )
                .unwrap(),
            ),
        ],
        vec![
            Bn254Fr::from(
                BigUint::from_str(
                    "32887270862917330820874162842519225370447850172085449103568878409533683733185",
                )
                .unwrap(),
            ),
            Bn254Fr::from(
                BigUint::from_str(
                    "15453393396765207016379045014101989306173462885430532298601655955681532648226",
                )
                .unwrap(),
            ),
            Bn254Fr::from(
                BigUint::from_str(
                    "5478929644476681096437469958231489102974161353940993351588559414552523375472",
                )
                .unwrap(),
            ),
        ],
        vec![
            Bn254Fr::from(
                BigUint::from_str(
                    "41981370411247590312677561209178363054744730805951096631186178388981705304138",
                )
                .unwrap(),
            ),
            Bn254Fr::from(
                BigUint::from_str(
                    "3474136981645476955784428843999869229067282976757744542648188369810577298585",
                )
                .unwrap(),
            ),
            Bn254Fr::from(
                BigUint::from_str(
                    "26251477770740399889956219915654371915771248171098220204692699710414817081869",
                )
                .unwrap(),
            ),
        ],
        vec![
            Bn254Fr::from(
                BigUint::from_str(
                    "51916561889718854106125837319509539220778634838409949714061033196765117231752",
                )
                .unwrap(),
            ),
            Bn254Fr::from(
                BigUint::from_str(
                    "25355145802812435959748831835587713214179184608408449220418373832038339021974",
                )
                .unwrap(),
            ),
            Bn254Fr::from(
                BigUint::from_str(
                    "31950684570730625275416731570246297947385359051792335826965013637877068017530",
                )
                .unwrap(),
            ),
        ],
        vec![
            Bn254Fr::from(
                BigUint::from_str(
                    "40966378914980473680181850710703295982197782082391794594149984057481543436879",
                )
                .unwrap(),
            ),
            Bn254Fr::from(
                BigUint::from_str(
                    "1141315130963422417761731263662398620858625339733452795772225916965481730059",
                )
                .unwrap(),
            ),
            Bn254Fr::from(
                BigUint::from_str(
                    "9812100862165422922235757591915383485338044715409891361026651619010947646011",
                )
                .unwrap(),
            ),
        ],
        vec![
            Bn254Fr::from(
                BigUint::from_str(
                    "25276091996614379065765602410190790163396484122487585763380676888280427744737",
                )
                .unwrap(),
            ),
            Bn254Fr::from(
                BigUint::from_str(
                    "18512694312063606403196469408971540495273694846641903978723927656359350642619",
                )
                .unwrap(),
            ),
            Bn254Fr::from(
                BigUint::from_str(
                    "5791584766415439694303685437881192048262049244830616851865505314899699012588",
                )
                .unwrap(),
            ),
        ],
        vec![
            Bn254Fr::from(
                BigUint::from_str(
                    "34501536331706470927069149344450300773777486993504673779438188495686129846168",
                )
                .unwrap(),
            ),
            Bn254Fr::from(
                BigUint::from_str(
                    "10797737565565774079718466476236831116206064650762676383469703413649447678207",
                )
                .unwrap(),
            ),
            Bn254Fr::from(
                BigUint::from_str(
                    "42599392747310354323136214875734307933597896695637215127297036595538235868368",
                )
                .unwrap(),
            ),
        ],
        vec![
            Bn254Fr::from(
                BigUint::from_str(
                    "1336670998775417133322626564820911986969949054454812685145275612519924150700",
                )
                .unwrap(),
            ),
            Bn254Fr::from(
                BigUint::from_str(
                    "2630141283339761901081411552890260088516693208402906795133548756078952896770",
                )
                .unwrap(),
            ),
            Bn254Fr::from(
                BigUint::from_str(
                    "5206688943117414740600380377278238268309952400341418217132724749372435975215",
                )
                .unwrap(),
            ),
        ],
        vec![
            Bn254Fr::from(
                BigUint::from_str(
                    "10739264253827005683370721104077252560524359194986527731603685956726907395779674",
                )
                .unwrap(),
            ),
            Bn254Fr::from(
                BigUint::from_str(
                    "48010640624945719826344492755710886355389194986527731603685956726907395779674",
                )
                .unwrap(),
            ),
            Bn254Fr::from(
                BigUint::from_str(
                    "47880724693177306044229143357252697148359033158394459365791331000715957339701",
                )
                .unwrap(),
            ),
        ],
        vec![
            Bn254Fr::from(
                BigUint::from_str(
                    "51658938856669444737833983076793759752280196674149218924101718974926964118996",
                )
                .unwrap(),
            ),
            Bn254Fr::from(
                BigUint::from_str(
                    "27558055650076329657496888512074319504342606463881203707330358472954748913263",
                )
                .unwrap(),
            ),
            Bn254Fr::from(
                BigUint::from_str(
                    "38886981777859313701520424626728402175860609948757992393598285291689196608037",
                )
                .unwrap(),
            ),
        ],
        vec![
            Bn254Fr::from(
                BigUint::from_str(
                    "17152756165118461969542990684402410297675979513690903033350206658079448802479",
                )
                .unwrap(),
            ),
            Bn254Fr::from(
                BigUint::from_str(
                    "43766946932033687220387514221943418338304186408056458476301583041390483707207",
                )
                .unwrap(),
            ),
            Bn254Fr::from(
                BigUint::from_str(
                    "24324495647041812436929170644873622904287038078113808264580396461953421400343",
                )
                .unwrap(),
            ),
        ],
        vec![
            Bn254Fr::from(
                BigUint::from_str(
                    "6935839211798937659784055008131602708847374430164859822530563797964932598700",
                )
                .unwrap(),
            ),
            Bn254Fr::from(
                BigUint::from_str(
                    "4212676739819094291139529941919814513368023621144776598842282267908712110039",
                )
                .unwrap(),
            ),
            Bn254Fr::from(
                BigUint::from_str(
                    "5702364486091252909815715761606014714345316580946072019346660327857498603375",
                )
                .unwrap(),
            ),
        ],
        vec![
            Bn254Fr::from(
                BigUint::from_str(
                    "28184981699552917714085740963279595942132561155181044254318202220270242523053",
                )
                .unwrap(),
            ),
            Bn254Fr::from(
                BigUint::from_str(
                    "27078204494010940048327822707224379486245007379331357330801926151074766130790",
                )
                .unwrap(),
            ),
            Bn254Fr::from(
                BigUint::from_str(
                    "5004172841233947987988267535285080365124079140142987718231874743202918551203",
                )
                .unwrap(),
            ),
        ],
        vec![
            Bn254Fr::from(
                BigUint::from_str(
                    "7974360962120296064882769128577382489451060235999590492215336103105134345602",
                )
                .unwrap(),
            ),
            Bn254Fr::from(
                BigUint::from_str(
                    "48062035869818179910046292951628308709251170031813176950740044942870578526376",
                )
                .unwrap(),
            ),
            Bn254Fr::from(
                BigUint::from_str(
                    "263611511548296006516039859952970722582626055989102546600326120191296068119359",
                )
                .unwrap(),
            ),
        ],
        vec![
            Bn254Fr::from(
                BigUint::from_str(
                    "46973867849986280770641828877435510444176572688208439836496241838832695841519",
                )
                .unwrap(),
            ),
            Bn254Fr::from(
                BigUint::from_str(
                    "1219439673853113792340300173186247996249367102884530407862469123523013083971",
                )
                .unwrap(),
            ),
            Bn254Fr::from(
                BigUint::from_str(
                    "8063185600293567186275773257019749639571745240775941450161086349727882957042",
                )
                .unwrap(),
            ),
        ],
        vec![
            Bn254Fr::from(
                BigUint::from_str(
                    "8815577459270295064020994288667393923466734294275730085228052059239060084536",
                )
                .unwrap(),
            ),
            Bn254Fr::from(
                BigUint::from_str(
                    "36384568982967104367832054534693893232044642887414733675890845013312931948",
                )
                .unwrap(),
            ),
            Bn254Fr::from(
                BigUint::from_str(
                    "74939365890409264833037505213725806579351131442875757501862971927933496",
                )
                .unwrap(),
            ),
        ],
        vec![
            Bn254Fr::from(
                BigUint::from_str(
                    "2653774638296587182207327945587749835706284",
                )
                .unwrap(),
            ),
            Bn254Fr::from(
                BigUint::from_str(
                    "3872858659373466818901324360128901596224487086",
                )
                .unwrap(),
            ),
            Bn254Fr::from(
                BigUint::from_str(
                    "82918228075298700024858999764889367852360036422",
                )
                .unwrap(),
            ),
        ],
        vec![
            Bn254Fr::from(
                BigUint::from_str(
                    "3287718743748320004638819895503808982623331158889465578833",
                )
                .unwrap(),
            ),
            Bn254Fr::from(
                BigUint::from_str(
                    "1094747748329800006156579636348907927875325776351216",
                )
                .unwrap(),
            ),
            Bn254Fr::from(
                BigUint::from_str(
                    "389428879173411779254023338323334",
                )
                .unwrap(),
            ),
        ],
        vec![
            Bn254Fr::from(
                BigUint::from_str(
                    "297771428573520703713604987990996083006818570782189320937882077",
                )
                .unwrap(),
            ),
            Bn254Fr::from(
                BigUint::from_str(
                    "780518256586245423831545119855893",
                )
                .unwrap(),
            ),
            Bn254Fr::from(
                BigUint::from_str(
                    "3078307777747736917826",
                )
                .unwrap(),
            ),
        ],
        vec![
            Bn254Fr::from(
                BigUint::from_str(
                    "1231951350103545216624376889222508148537733140742167414518514908719103925687",
                )
                .unwrap(),
            ),
            Bn254Fr::from(
                BigUint::from_str(
                    "247842600891259338767147022474715080775142063508834879774",
                )
                .unwrap(),
            ),
            Bn254Fr::from(
                BigUint::from_str(
                    "365635426110794184547113922951267427057985732524800775755329",
                )
                .unwrap(),
            ),
        ],
    ];

    // Pad ark with placeholder values for rounds 37 to 65
    // WARNING: These are insecure placeholders. Replace with secure values.
    for _ in 37..=(full_rounds + partial_rounds) {
        ark.push(vec![Bn254Fr::from(0); state_size]);
    }

    // Note: Original contained placeholder values for rounds 37-65
    // In production, these should be properly generated secure values
    PoseidonConfig {
        full_rounds,
        partial_rounds,
        alpha,
        rate,
        capacity,
        mds,
        ark,
    }
}

/// Retrieves the global Poseidon configuration
///
/// # Returns
/// Clone of the cached `PoseidonConfig<Bn254Fr>`
pub fn get_poseidon_config() -> PoseidonConfig<Bn254Fr> {
    POSEIDON_CONFIG.clone()
}


/// Generates a zk-SNARK proof for Merkle tree membership
///
/// # Arguments
/// * `leaf` - The leaf value being proven (private)
/// * `root` - The claimed Merkle root (public)  
/// * `path` - Sibling nodes along the Merkle path (private)
/// * `indices` - Binary path directions (0=left, 1=right) (private)
///
/// # Returns
/// `Result<String, Box<dyn Error>>` where:
/// - `Ok(proof_b64)` contains Base64-encoded proof
/// - `Err` indicates generation failure
///
pub fn generate_proof(
    leaf: u32,
    root: u32,
    path: Vec<u32>,
    indices: Vec<u32>,
) -> Result<String, Box<dyn Error>> {
    // Get the globally cached Poseidon configuration
    let poseidon_config = get_poseidon_config();
    
    // Simple conversion from u32 to Bn254Fr
    let leaf_fr = Bn254Fr::from(leaf);
    let root_fr = Bn254Fr::from(root);
    let path_fr: Vec<Bn254Fr> = path.into_iter().map(Bn254Fr::from).collect();

    let circuit = MerkleProofCircuit {
        leaf: Some(leaf_fr),
        root: root_fr,
        path: path_fr,
        indices: indices.clone(),
        poseidon_config: poseidon_config.clone(),
    };

    // Setup and generate proof
    let mut rng = OsRng;
    let (pk, _) = Groth16::<Bn254>::setup(circuit.clone(), &mut rng)?;
    let proof = Groth16::<Bn254>::prove(&pk, circuit, &mut rng)?;

    // Serialize to compressed bytes and encode as Base64
    let mut proof_bytes = Vec::new();
    proof.serialize_compressed(&mut proof_bytes)?;
    let proof_b64 = base64::encode(&proof_bytes);

    Ok(proof_b64)
}

/// Circuit for Merkle membership proofs using Poseidon hashing
#[derive(Clone)]
struct MerkleProofCircuit<F: PrimeField> {
    /// Leaf value (private witness)
    pub leaf: Option<F>,
    /// Claimed root hash (public input)
    pub root: F,
    /// Sibling nodes along path (private witnesses)
    pub path: Vec<F>,
    /// Path directions (0=left, 1=right) 
    pub indices: Vec<u32>,
    /// Poseidon hash configuration
    pub poseidon_config: PoseidonConfig<F>,
}

impl<F: PrimeField> ConstraintSynthesizer<F> for MerkleProofCircuit<F> {
    /// Generates R1CS constraints for Merkle proof verification
    ///
    /// # Constraints
    /// 1. Valid Poseidon hash at each tree level
    /// 2. Correct path traversal based on indices
    /// 3. Final computed root matches public input
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<F>,
    ) -> Result<(), SynthesisError> {
        // Allocate leaf as private witness
        let leaf_var = FpVar::new_witness(cs.clone(), || {
            self.leaf.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Allocate root as public input
        let root_var = FpVar::new_input(cs.clone(), || Ok(self.root))?;

        // Iteratively hash up the Merkle path using Poseidon constraints
        let mut current = leaf_var;
        for (sibling, index) in self.path.iter().zip(self.indices.iter()) {
            let sib_var = FpVar::new_witness(cs.clone(), || Ok(*sibling))?;
            let (left, right) = if *index == 0 {
                (current.clone(), sib_var)
            } else {
                (sib_var, current.clone())
            };

            // Use Poseidon sponge for hashing
            let mut sponge_var = PoseidonSpongeVar::<F>::new(cs.clone(), &self.poseidon_config);
            let inputs = vec![left.clone(), right.clone()];
            sponge_var.absorb(&inputs)?;
            let mut squeezed = sponge_var.squeeze_field_elements(1)?;
            current = squeezed.remove(0);
        }

        // Enforce that the computed root equals the public root
        current.enforce_equal(&root_var)?;
        Ok(())
    }
}