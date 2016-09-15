package edu.cmu.iccb;


import java.util.Arrays;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import edu.cmu.iccb.services.ImageService;

@Controller
public class HomeController {
	
	//@Value("${cloud.github.credentials.ClientId}")
	private String clientsecret="81e246b92b9a18b2b078708c7d122a5615dfd5c1";
	
	//@Value("${cloud.github.credentials.ClientS}")
	private String clientid="cc3ba39d2683bd3b59bc";
	
    private ImageService imageService;
    
    @Autowired
	public void setImageService(ImageService imageService) {
		this.imageService = imageService;
	}

    public ImageService getImageService() {
		return imageService;
	}
    


    @RequestMapping(method = RequestMethod.GET, value = "/images")
    public String provideUploadInfo(Model model, RedirectAttributes redirectAttributes) {

        List<String> imageIds = imageService.getUploadedImages();        
        model.addAttribute("files", imageIds); 
        return "uploadForm";
        //return "redirect:https://github.com/login/oauth/authorize?client_id=cc3ba39d2683bd3b59bc";
    }

    @RequestMapping(method = RequestMethod.POST, value = "/images")
    public String handleFileUpload(@RequestParam("file") MultipartFile file,
                                   RedirectAttributes redirectAttributes) {

        String name = file.getOriginalFilename();

        try {        	
        	imageService.saveImage(name, file.getInputStream());           
        }
        catch (Exception e) {
            redirectAttributes.addFlashAttribute("message", name + " failed to upload");
        }

        return "redirect:/images";
    }

    
    @RequestMapping(method = RequestMethod.GET, value = "/")
    public String loginForm(Model model, RedirectAttributes redirectAttributes) {   
        return "login";
    }
    
    
}
